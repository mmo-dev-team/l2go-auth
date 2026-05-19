// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"crypto/rand"
)

const cryptKeysSize = 20 // Number of pre-generated keys in the pool

var cryptKeys [cryptKeysSize][16]byte // Pool of 128-bit Blowfish keys

var suffixKey = [8]byte{0xc8, 0x27, 0x93, 0x01, 0xa1, 0x6c, 0x31, 0x97} // Static suffix for Blowfish keys (8 bytes)

// GetRandomBlowFishKey returns a random Blowfish key slice from the pre-generated pool.
// It uses the provided index to guarantee a fast, constant-time and lock-free lookup.
func GetRandomBlowFishKey(idx int) []byte {
	return cryptKeys[uint(idx)%uint(cryptKeysSize)][:]
}

// GenerateLoginBlowFishKeys populates the key pool with secure random keys for Login server use.
// This should be called once during the server initialization.
func GenerateLoginBlowFishKeys() {
	for i := 0; i < cryptKeysSize; i++ {
		if _, err := rand.Read(cryptKeys[i][:]); err != nil {
			panic("crypto: failed to generate secure blowfish keys: " + err.Error())
		}
	}
}

// GenerateGameBlowFishKey generates a unique 16-byte Blowfish key for a specific session.
// The first 8 bytes are cryptographically secure random data, and the last 8 bytes are the static suffix.
func GenerateGameBlowFishKey() ([16]byte, error) {
	var key [16]byte

	// 1. Generate the first 8 bytes (the dynamic part of the key for session security)
	if _, err := rand.Read(key[0:8]); err != nil {
		return key, err
	}

	// 2. Copy the static suffix into the remaining 8 bytes
	copy(key[8:16], suffixKey[:])
	return key, nil
}
