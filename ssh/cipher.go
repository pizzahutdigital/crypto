// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/aes"
	"crypto/des"
	"crypto/cipher"
	"crypto/rc4"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

type cryptDirection byte

const (
	encrypt = cryptDirection(iota)
	decrypt
)

const (
	packetSizeMultiple = 16 // TODO(huin) this should be determined by the cipher.

	// RFC 4253 section 6.1 defines a minimum packet size of 32768 that implementations
	// MUST be able to process (plus a few more kilobytes for padding and mac). The RFC
	// indicates implementations SHOULD be able to handle larger packet sizes, but then
	// waffles on about reasonable limits.
	//
	// OpenSSH caps their maxPacket at 256kB so we choose to do
	// the same. maxPacket is also used to ensure that uint32
	// length fields do not overflow, so it should remain well
	// below 4G.
	maxPacket = 256 * 1024
)

// noneCipher implements cipher.Stream and provides no encryption. It is used
// by the transport before the first key-exchange.
type noneCipher struct{}

func (c noneCipher) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}

func newAESCTR(key, iv []byte) (cipher.Stream, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(c, iv), nil
}

func newAESCBC(dir cryptDirection, key, iv []byte) (cipher.BlockMode, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if dir == encrypt {
		return cipher.NewCBCEncrypter(c, iv), nil
	} else if dir == decrypt {
		return cipher.NewCBCDecrypter(c, iv), nil
	} else {
		panic(fmt.Sprintf("invalid crypt direction: %v", dir))
	}
}

func new3DESCBC(dir cryptDirection, key, iv []byte) (cipher.BlockMode, error) {
	c, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if dir == encrypt {
		return cipher.NewCBCEncrypter(c, iv), nil
	} else if dir == decrypt {
		return cipher.NewCBCDecrypter(c, iv), nil
	} else {
		panic(fmt.Sprintf("invalid crypt direction: %v", dir))
	}
}

func newRC4(key, iv []byte) (cipher.Stream, error) {
	return rc4.NewCipher(key)
}

type cipherMode interface {
	createPacketCipher(dir cryptDirection, d direction, algs directionAlgorithms, macKey, key, iv []byte) (packetCipher, error)
	KeySize() int
	IvSize() int
}

type streamCipherMode struct {
	keySize    int
	ivSize     int
	skip       int
	createFunc func(key, iv []byte) (cipher.Stream, error)
}

func (c *streamCipherMode) KeySize() int {
	return c.keySize
}

func (c *streamCipherMode) IvSize() int {
	return c.ivSize
}

func (c *streamCipherMode) createStream(key, iv []byte) (cipher.Stream, error) {
	if len(key) < c.keySize {
		panic("ssh: key length too small for cipher")
	}
	if len(iv) < c.ivSize {
		panic("ssh: iv too small for cipher")
	}

	stream, err := c.createFunc(key[:c.keySize], iv[:c.ivSize])
	if err != nil {
		return nil, err
	}

	var streamDump []byte
	if c.skip > 0 {
		streamDump = make([]byte, 512)
	}

	for remainingToDump := c.skip; remainingToDump > 0; {
		dumpThisTime := remainingToDump
		if dumpThisTime > len(streamDump) {
			dumpThisTime = len(streamDump)
		}
		stream.XORKeyStream(streamDump[:dumpThisTime], streamDump[:dumpThisTime])
		remainingToDump -= dumpThisTime
	}

	return stream, nil
}

func (scm *streamCipherMode) createPacketCipher(dir cryptDirection, d direction, algs directionAlgorithms, macKey, key, iv []byte) (packetCipher, error) {
	c := &streamPacketCipher{
		mac: macModes[algs.MAC].new(macKey),
	}
	c.macResult = make([]byte, c.mac.Size())

	var err error
	c.cipher, err = scm.createStream(key, iv)
	if err != nil {
		return nil, err
	}

	return c, nil
}

type blockCipherMode struct {
	keySize    int
	ivSize     int
	createFunc func(d cryptDirection, key, iv []byte) (cipher.BlockMode, error)
}

func (c *blockCipherMode) KeySize() int {
	return c.keySize
}

func (c *blockCipherMode) IvSize() int {
	return c.ivSize
}

func (c *blockCipherMode) createBlock(d cryptDirection, key, iv []byte) (cipher.BlockMode, error) {
	if len(key) < c.keySize {
		panic("ssh: key length too small for cipher")
	}
	if len(iv) < c.ivSize {
		panic("ssh: iv too small for cipher")
	}

	stream, err := c.createFunc(d, key[:c.keySize], iv[:c.ivSize])
	if err != nil {
		return nil, err
	}

	return stream, nil
}

func (scm *blockCipherMode) createPacketCipher(dir cryptDirection, d direction, algs directionAlgorithms, macKey, key, iv []byte) (packetCipher, error) {
	c := &blockPacketCipher{
		mac: macModes[algs.MAC].new(macKey),
	}
	c.macResult = make([]byte, c.mac.Size())

	var err error
	c.cipher, err = scm.createBlock(dir, key, iv)
	if err != nil {
		return nil, err
	}

	return c, nil
}


// cipherModes documents properties of supported ciphers. Ciphers not included
// are not supported and will not be negotiated, even if explicitly requested in
// ClientConfig.Crypto.Ciphers.
var cipherModes = map[string]cipherMode{
	// Ciphers from RFC4344, which introduced many CTR-based ciphers. Algorithms
	// are defined in the order specified in the RFC.
	"aes128-ctr": &streamCipherMode{16, aes.BlockSize, 0, newAESCTR},
	"aes192-ctr": &streamCipherMode{24, aes.BlockSize, 0, newAESCTR},
	"aes256-ctr": &streamCipherMode{32, aes.BlockSize, 0, newAESCTR},

	// Ciphers from RFC4345, which introduces security-improved arcfour ciphers.
	// They are defined in the order specified in the RFC.
	"arcfour128": &streamCipherMode{16, 0, 1536, newRC4},
	"arcfour256": &streamCipherMode{32, 0, 1536, newRC4},

	// Cipher defined in RFC 4253, which describes SSH Transport Layer Protocol.
	// Note that this cipher is not safe, as stated in RFC 4253: "Arcfour (and
	// RC4) has problems with weak keys, and should be used with caution."
	// RFC4345 introduces improved versions of Arcfour.
	"arcfour": &streamCipherMode{16, 0, 0, newRC4},

	// AES-GCM is not a stream cipher, so it is constructed with a
	// special case. If we add any more non-stream ciphers, we
	// should invest a cleaner way to do this.
	gcmCipherID: &streamCipherMode{16, 12, 0, nil},

	"aes128-cbc": &blockCipherMode{16, aes.BlockSize, newAESCBC},
	"aes192-cbc": &blockCipherMode{24, aes.BlockSize, newAESCBC},
	"aes256-cbc": &blockCipherMode{32, aes.BlockSize, newAESCBC},
	"3des-cbc":   &blockCipherMode{24, des.BlockSize, new3DESCBC},
}

// prefixLen is the length of the packet prefix that contains the packet length
// and number of padding bytes.
const prefixLen = 5

// streamPacketCipher is a packetCipher using a stream cipher.
type streamPacketCipher struct {
	mac    hash.Hash
	cipher cipher.Stream

	// The following members are to avoid per-packet allocations.
	prefix      [prefixLen]byte
	seqNumBytes [4]byte
	padding     [2 * packetSizeMultiple]byte
	packetData  []byte
	macResult   []byte
}

// readPacket reads and decrypt a single packet from the reader argument.
func (s *streamPacketCipher) readPacket(seqNum uint32, r io.Reader) ([]byte, error) {
	if _, err := io.ReadFull(r, s.prefix[:]); err != nil {
		return nil, err
	}

	s.cipher.XORKeyStream(s.prefix[:], s.prefix[:])
	length := binary.BigEndian.Uint32(s.prefix[0:4])
	paddingLength := uint32(s.prefix[4])

	var macSize uint32
	if s.mac != nil {
		s.mac.Reset()
		binary.BigEndian.PutUint32(s.seqNumBytes[:], seqNum)
		s.mac.Write(s.seqNumBytes[:])
		s.mac.Write(s.prefix[:])
		macSize = uint32(s.mac.Size())
	}

	if length <= paddingLength+1 {
		return nil, errors.New("ssh: invalid packet length, packet too small")
	}

	if length > maxPacket {
		return nil, errors.New("ssh: invalid packet length, packet too large")
	}

	// the maxPacket check above ensures that length-1+macSize
	// does not overflow.
	if uint32(cap(s.packetData)) < length-1+macSize {
		s.packetData = make([]byte, length-1+macSize)
	} else {
		s.packetData = s.packetData[:length-1+macSize]
	}

	if _, err := io.ReadFull(r, s.packetData); err != nil {
		return nil, err
	}
	mac := s.packetData[length-1:]
	data := s.packetData[:length-1]
	s.cipher.XORKeyStream(data, data)

	if s.mac != nil {
		s.mac.Write(data)
		s.macResult = s.mac.Sum(s.macResult[:0])
		if subtle.ConstantTimeCompare(s.macResult, mac) != 1 {
			return nil, errors.New("ssh: MAC failure")
		}
	}

	return s.packetData[:length-paddingLength-1], nil
}

// writePacket encrypts and sends a packet of data to the writer argument
func (s *streamPacketCipher) writePacket(seqNum uint32, w io.Writer, rand io.Reader, packet []byte) error {
	if len(packet) > maxPacket {
		return errors.New("ssh: packet too large")
	}

	paddingLength := packetSizeMultiple - (prefixLen+len(packet))%packetSizeMultiple
	if paddingLength < 4 {
		paddingLength += packetSizeMultiple
	}

	length := len(packet) + 1 + paddingLength
	binary.BigEndian.PutUint32(s.prefix[:], uint32(length))
	s.prefix[4] = byte(paddingLength)
	padding := s.padding[:paddingLength]
	if _, err := io.ReadFull(rand, padding); err != nil {
		return err
	}

	if s.mac != nil {
		s.mac.Reset()
		binary.BigEndian.PutUint32(s.seqNumBytes[:], seqNum)
		s.mac.Write(s.seqNumBytes[:])
		s.mac.Write(s.prefix[:])
		s.mac.Write(packet)
		s.mac.Write(padding)
	}

	s.cipher.XORKeyStream(s.prefix[:], s.prefix[:])
	s.cipher.XORKeyStream(packet, packet)
	s.cipher.XORKeyStream(padding, padding)

	if _, err := w.Write(s.prefix[:]); err != nil {
		return err
	}
	if _, err := w.Write(packet); err != nil {
		return err
	}
	if _, err := w.Write(padding); err != nil {
		return err
	}

	if s.mac != nil {
		s.macResult = s.mac.Sum(s.macResult[:0])
		if _, err := w.Write(s.macResult); err != nil {
			return err
		}
	}

	return nil
}

type gcmCipher struct {
	aead   cipher.AEAD
	prefix [4]byte
	iv     []byte
	buf    []byte
}

func newGCMCipher(iv, key, macKey []byte) (packetCipher, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	return &gcmCipher{
		aead: aead,
		iv:   iv,
	}, nil
}

const gcmTagSize = 16

func (c *gcmCipher) writePacket(seqNum uint32, w io.Writer, rand io.Reader, packet []byte) error {
	// Pad out to multiple of 16 bytes. This is different from the
	// stream cipher because that encrypts the length too.
	padding := byte(packetSizeMultiple - (1+len(packet))%packetSizeMultiple)
	if padding < 4 {
		padding += packetSizeMultiple
	}

	length := uint32(len(packet) + int(padding) + 1)
	binary.BigEndian.PutUint32(c.prefix[:], length)
	if _, err := w.Write(c.prefix[:]); err != nil {
		return err
	}

	if cap(c.buf) < int(length) {
		c.buf = make([]byte, length)
	} else {
		c.buf = c.buf[:length]
	}

	c.buf[0] = padding
	copy(c.buf[1:], packet)
	if _, err := io.ReadFull(rand, c.buf[1+len(packet):]); err != nil {
		return err
	}
	c.buf = c.aead.Seal(c.buf[:0], c.iv, c.buf, c.prefix[:])
	if _, err := w.Write(c.buf); err != nil {
		return err
	}
	c.incIV()

	return nil
}

func (c *gcmCipher) incIV() {
	for i := 4 + 7; i >= 4; i-- {
		c.iv[i]++
		if c.iv[i] != 0 {
			break
		}
	}
}

func (c *gcmCipher) readPacket(seqNum uint32, r io.Reader) ([]byte, error) {
	if _, err := io.ReadFull(r, c.prefix[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(c.prefix[:])
	if length > maxPacket {
		return nil, errors.New("ssh: max packet length exceeded.")
	}

	if cap(c.buf) < int(length+gcmTagSize) {
		c.buf = make([]byte, length+gcmTagSize)
	} else {
		c.buf = c.buf[:length+gcmTagSize]
	}

	if _, err := io.ReadFull(r, c.buf); err != nil {
		return nil, err
	}

	plain, err := c.aead.Open(c.buf[:0], c.iv, c.buf, c.prefix[:])
	if err != nil {
		return nil, err
	}
	c.incIV()

	padding := plain[0]
	if padding < 4 || padding >= 20 {
		return nil, fmt.Errorf("ssh: illegal padding %d", padding)
	}

	if int(padding+1) >= len(plain) {
		return nil, fmt.Errorf("ssh: padding %d too large", padding)
	}
	plain = plain[1 : length-uint32(padding)]
	return plain, nil
}

type blockPacketCipher struct {
	mac    hash.Hash
	cipher cipher.BlockMode

	// The following members are to avoid per-packet allocations.
	prefix      [prefixLen]byte
	seqNumBytes [4]byte
	padding     [2 * packetSizeMultiple]byte
	packetData  []byte
	macResult   []byte
}

// blockedLength calculates the number of bytes required to hold length bytes
// of data, within the given block size multiple.
func blockedLength(length, blockSize int) int {
	numBlocks := length / blockSize
	if length%blockSize > 0 {
		numBlocks++
	}
	return numBlocks * blockSize
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *blockPacketCipher) readPacket(seqNum uint32, r io.Reader) ([]byte, error) {
	minPacketSizeMultiple := int(8)
	minPacketSize         := int(16)
	maxPacketSize         := uint32(36000)
	minPaddingSize        := uint32(4) // TODO(huin) should this be configurable?

	blockSize := s.cipher.BlockSize()

	// Read the header, which will include some of the subsequent data in the
	// case of block ciphers - this is copied back to the payload later.
	firstBlockLength := blockedLength(5, blockSize)
	// How many bytes of payload/padding will be read with this first read.
	overreadLength := firstBlockLength - 5
	firstBlock := make([]byte, firstBlockLength)
	if _, err := io.ReadFull(r, firstBlock); err != nil {
		return nil, err
	}

	s.cipher.CryptBlocks(firstBlock, firstBlock)

	length := binary.BigEndian.Uint32(firstBlock[:])
	if length > maxPacket {
		return nil, errors.New("ssh: max packet length exceeded.")
	}

	paddingLength := uint32(firstBlock[4])

	if paddingLength < minPaddingSize {
		return nil, errors.New("invalid padding length")
	}
	if length-paddingLength < 1 {
		return nil, errors.New("invalid packet length")
	}
	if length > maxPacketSize {
		return nil, errors.New("packet too large")
	}
	if length+4 < uint32(maxInt(minPacketSize, blockSize)) {
		return nil, errors.New("packet too small")
	}
	// The length of the packet (including the length field but not the MAC) must
	// be a multiple of the block size or 8, whichever is larger.
	if (length+4)%uint32(maxInt(minPacketSizeMultiple, blockSize)) != 0 {
		return nil, errors.New("invalid packet length multiple")
	}

	var macSize uint32
	if s.mac != nil {
		macSize = uint32(s.mac.Size())
	}

	// Various positions/lengths within the payload/padding buffer:
	cryptedStart := overreadLength
	paddingStart := length - paddingLength - 1
	macStart := paddingStart + paddingLength
	bufferLength := macStart + macSize

	packet := make([]byte, bufferLength)
	if _, err := io.ReadFull(r, packet[cryptedStart:]); err != nil {
		return nil, err
	}
	mac := packet[macStart:]

	// Copy the previously decrypted bytes in at the start.
	copy(packet[:cryptedStart], firstBlock[5:])

	// Decrypt the remainder of the packet.
	remainingCrypted := packet[cryptedStart:macStart]
	s.cipher.CryptBlocks(remainingCrypted, remainingCrypted)

	if s.mac != nil {
		s.mac.Reset()
		seqNumBytes := []byte{
			byte(seqNum >> 24),
			byte(seqNum >> 16),
			byte(seqNum >> 8),
			byte(seqNum),
		}
		s.mac.Write(seqNumBytes)
		s.mac.Write(firstBlock[:5])
		s.mac.Write(packet[:macStart])
		s.macResult = s.mac.Sum(s.macResult[:0])
		if subtle.ConstantTimeCompare(s.macResult, mac) != 1 {
			return nil, errors.New("ssh: MAC failure")
		}
	}

	return packet[:paddingStart], nil
}

func (s *blockPacketCipher) writePacket(seqNum uint32, w io.Writer, rand io.Reader, packet []byte) error {
	minPacketSizeMultiple := int(8)
	minPaddingSize        := int(4) // TODO(huin) should this be configurable?

	// Length of encrypted portion of the packet (header, payload, padding).
	effectiveBlockSize := maxInt(minPacketSizeMultiple, s.cipher.BlockSize())

	// Enforce minimum padding and packet size.
	encLength := maxInt(5+len(packet)+minPaddingSize, minPaddingSize)

	// Enforce block size.
	encLength = blockedLength(encLength, effectiveBlockSize)

	length := encLength - 4
	paddingLength := length - (1 + len(packet))

	// Overall buffer contains: header, payload, padding.
	buffer := make([]byte, 5+len(packet)+paddingLength)

	// Packet header.
	buffer[0] = byte(length >> 24)
	buffer[1] = byte(length >> 16)
	buffer[2] = byte(length >> 8)
	buffer[3] = byte(length)
	buffer[4] = byte(paddingLength)

	// Payload.
	dataEnd := len(buffer) - paddingLength
	copy(buffer[5:dataEnd], packet)

	// Padding.
	paddingEnd := dataEnd + paddingLength
	_, err := io.ReadFull(rand, buffer[dataEnd:paddingEnd])
	if err != nil {
		return err
	}

	if s.mac != nil {
		s.mac.Reset()
		seqNumBytes := []byte{
			byte(seqNum >> 24),
			byte(seqNum >> 16),
			byte(seqNum >> 8),
			byte(seqNum),
		}
		s.mac.Write(seqNumBytes)
		s.mac.Write(buffer)
	}

	s.cipher.CryptBlocks(buffer, buffer)

	if _, err := w.Write(buffer); err != nil {
		return err
	}

	if s.mac != nil {
		if _, err := w.Write(s.mac.Sum(nil)); err != nil {
			return err
		}
	}

	return err
}

