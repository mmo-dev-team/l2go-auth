// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"encoding/binary"
	"math/rand/v2"

	"github.com/mmo-dev-team/l2go-auth/pkg/crypto"
	"github.com/mmo-dev-team/l2go-auth/pkg/network"
)

// Crypt handles packet encryption and decryption using the Blowfish algorithm and a custom XOR-based checksum.
type Crypt struct {
	cipher     *crypto.BlowfishCipher
	updatedKey bool
}

// StaticKey is the default blowfish key used for the initial handshake.
var StaticKey = []byte{0x6b, 0x60, 0xcb, 0x5b, 0x82, 0xce, 0x90, 0xb1, 0xcc, 0x2b, 0x6c, 0x55, 0x6c, 0x6c, 0x6c, 0x6c}

// staticCipher is the read-only Blowfish cipher for the initial handshake (Init) packet.
var staticCipher = crypto.NewBlowfishCipher(StaticKey)

// NewCrypt creates a new Crypt instance with the given Blowfish key.
func NewCrypt(key []byte) *Crypt {
	return &Crypt{
		updatedKey: false,
		cipher:     crypto.NewBlowfishCipher(key),
	}
}

// Encrypt encrypts the packet content, adding a checksum and padding as required by the protocol.
func (c *Crypt) Encrypt(w *network.PacketWriter) {
	// Exclude the 2-byte packet length header from payload calculations
	payloadLen := len(w.Bytes()) - 2

	reserve := 12 // Default reserve for checksum (4 bytes) and potential XOR key (4 bytes) + overhead
	if !c.updatedKey {
		reserve = 16 // First packet (Init) requires 16 bytes for Blowfish padding and XOR key
	}

	w.Extend(reserve)
	payloadLen += reserve

	// Blowfish requires 8-byte block alignment
	pad := 8 - (payloadLen % 8)
	if pad != 8 {
		w.Extend(pad)
		payloadLen += pad
	}

	data := w.Bytes()[2:] // Skip length header

	if !c.updatedKey {
		c.updatedKey = true
		xorKey := rand.Uint32()
		encXorPass(data, uint32(payloadLen), xorKey)
	}

	c.cipher.CipherRange(data, 0, payloadLen)
}

// Decrypt decrypts the given data using the Blowfish algorithm.
// It returns false if the data size is not a multiple of 8 or is empty.
func (c *Crypt) Decrypt(data []byte, size int) bool {
	// Blowfish block size is 8 bytes
	if size%8 != 0 || size <= 0 {
		return false
	}

	c.cipher.DecipherRange(data, 0, size)
	return true
}

// EncryptStatic encrypts the initial Init packet in place using the shared static Blowfish cipher.
func EncryptStatic(w *network.PacketWriter) {
	payloadLen := len(w.Bytes()) - 2 // Exclude the 2-byte packet length header

	reserve := 16 // Init packet reserves 16 bytes for Blowfish padding and XOR key
	w.Extend(reserve)
	payloadLen += reserve

	pad := 8 - (payloadLen % 8) // Blowfish requires 8-byte block alignment
	if pad != 8 {
		w.Extend(pad)
		payloadLen += pad
	}

	data := w.Bytes()[2:] // Skip length header

	xorKey := rand.Uint32()
	encXorPass(data, uint32(payloadLen), xorKey)

	staticCipher.CipherRange(data, 0, payloadLen)
}

// encXorPass applies a custom XOR-based checksum and obfuscation pass to the data.
func encXorPass(raw []byte, size uint32, key uint32) {
	if uint32(len(raw)) < size || size < 8 {
		return // Bounds Check Elimination (BCE) hint for the compiler
	}

	pos := uint32(4) // Start after the first 4 bytes
	stop := size - 8 // Reserve last 8 bytes for checksum/padding validation
	ecx := key

	// Main obfuscation loop processing 4 bytes at a time
	for pos < stop {
		// Read 4 bytes as uint32 using single MOV assembly instruction via LittleEndian
		edx := binary.LittleEndian.Uint32(raw[pos : pos+4])

		ecx += edx
		edx ^= ecx

		// Write back 4 bytes efficiently
		binary.LittleEndian.PutUint32(raw[pos:pos+4], edx)
		pos += 4
	}

	// Write the final computed checksum value to the remaining boundary block
	if pos+4 <= uint32(len(raw)) {
		binary.LittleEndian.PutUint32(raw[pos:pos+4], ecx)
	}
}
