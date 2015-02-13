// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"testing"
)

func TestDefaultCiphersExist(t *testing.T) {
	for _, cipherAlgo := range supportedCiphers {
		if _, ok := cipherModes[cipherAlgo]; !ok {
			t.Errorf("default cipher %q is unknown", cipherAlgo)
		}
	}
}

type kexAlgBundle struct {
	kr   *kexResult
	algs directionAlgorithms
}

func TestPacketCiphers(t *testing.T) {
	for cipher := range cipherModes {
		kexAlgs := []*kexAlgBundle{
			&kexAlgBundle{
				kr: &kexResult{Hash: crypto.SHA1},
				algs: directionAlgorithms{
					Cipher:      cipher,
					MAC:         "hmac-sha1",
					Compression: "none",
				},
			},
			&kexAlgBundle{
				kr: &kexResult{Hash: crypto.MD5},
				algs: directionAlgorithms{
					Cipher:      cipher,
					MAC:         "hmac-md5",
					Compression: "none",
				},
			},
		}
		for _, kexAlg := range kexAlgs {
			kr := kexAlg.kr
			algs := kexAlg.algs
			client, err := newPacketCipher(encrypt, clientKeys, algs, kr)
			if err != nil {
				t.Errorf("newPacketCipher(client, %q): %v", cipher, err)
				continue
			}
			server, err := newPacketCipher(decrypt, clientKeys, algs, kr)
			if err != nil {
				t.Errorf("newPacketCipher(client, %q): %v", cipher, err)
				continue
			}

			want := "bla bla"
			input := []byte(want)
			buf := &bytes.Buffer{}
			if err := client.writePacket(0, buf, rand.Reader, input); err != nil {
				t.Errorf("writePacket(%q): %v", cipher, err)
				continue
			}

			packet, err := server.readPacket(0, buf)
			if err != nil {
				t.Errorf("readPacket(%q): %v", cipher, err)
				continue
			}

			if string(packet) != want {
				t.Errorf("roundtrip(%q): got %q, want %q", cipher, packet, want)
			}
		}
	}
}
