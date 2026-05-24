// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"crypto/rand"
)

const cryptKeysSize = 20 // Number of pre-generated keys in the pool

var loginCryptKeys, gameCryptKeys [cryptKeysSize][16]byte // Pools of 128-bit Blowfish keys

var suffixKey = [8]byte{0xc8, 0x27, 0x93, 0x01, 0xa1, 0x6c, 0x31, 0x97} // Static suffix for Blowfish keys (8 bytes)

// GetRandomBlowFishKey returns a random Blowfish key slice from the pre-generated pool.
// It uses the provided index to guarantee a fast, constant-time and lock-free lookup.
func GetRandomBlowFishKey(idx int) []byte {
	return loginCryptKeys[uint(idx)%uint(cryptKeysSize)][:]
}

// GenerateLoginBlowFishKeys populates the key pool with secure random keys for Login server use.
// This should be called once during the server initialization.
func GenerateLoginBlowFishKeys() {
	var entropy [cryptKeysSize * 16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		panic("crypto: failed to generate secure login blowfish keys: " + err.Error())
	}
	for i := 0; i < cryptKeysSize; i++ {
		copy(loginCryptKeys[i][:], entropy[i*16:(i+1)*16])
	}
}

// GetRandomGameBlowFishKey returns a random Blowfish key slice from the pre-generated pool for Game server use.
// It uses the provided index to guarantee a fast, constant-time and lock-free lookup.
func GetRandomGameBlowFishKey(idx int) []byte {
	return gameCryptKeys[uint(idx)%uint(cryptKeysSize)][:]
}

// GenerateGameBlowFishKeys populates the key pool with secure random keys for Game server use.
// Each key consists of 8 random bytes followed by a static 8-byte suffix.
// This should be called once during the server initialization.
func GenerateGameBlowFishKeys() {
	var entropy [cryptKeysSize * 8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		panic("crypto: failed to generate first part of secure game blowfish keys: " + err.Error())
	}
	for i := 0; i < cryptKeysSize; i++ {
		copy(gameCryptKeys[i][0:8], entropy[i*8:(i+1)*8])
		copy(gameCryptKeys[i][8:16], suffixKey[:])
	}
}
