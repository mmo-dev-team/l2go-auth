// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"testing"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"
)

func TestCryptEncryptionPadding(t *testing.T) {
	key := StaticKey
	crypt := NewCrypt(key)

	w := network.GetPacketWriter()
	defer network.PutPacketWriter(w)

	w.WriteByte(0x01) // 1 byte payload
	w.PrependLength()

	crypt.Encrypt(w)

	data := w.Bytes()
	// Length header is 2 bytes. The rest is the payload which must be a multiple of 8.
	payloadSize := len(data) - 2
	if payloadSize%8 != 0 {
		t.Errorf("Expected payload size to be multiple of 8, got %d", payloadSize)
	}
}

func TestEncryptStaticPadding(t *testing.T) {
	w := network.GetPacketWriter()
	defer network.PutPacketWriter(w)

	w.WriteByte(0x00)
	w.WriteInt32(12345)
	w.PrependLength()

	before := len(w.Bytes())
	EncryptStatic(w)

	data := w.Bytes()
	payloadSize := len(data) - 2
	if payloadSize%8 != 0 {
		t.Errorf("Expected payload size to be multiple of 8, got %d", payloadSize)
	}
	if len(data) <= before {
		t.Errorf("Expected EncryptStatic to grow the buffer by reserve+padding, before=%d after=%d", before, len(data))
	}
}

func TestCryptDecryptSizeValidation(t *testing.T) {
	key := StaticKey
	crypt := NewCrypt(key)

	// Valid size (multiple of 8)
	validData := make([]byte, 16)
	if !crypt.Decrypt(validData, 16) {
		t.Error("Expected true for size 16")
	}

	// Invalid size
	invalidData := make([]byte, 15)
	if crypt.Decrypt(invalidData, 15) {
		t.Error("Expected false for size 15")
	}

	// Zero size
	if crypt.Decrypt([]byte{}, 0) {
		t.Error("Expected false for size 0")
	}
}
