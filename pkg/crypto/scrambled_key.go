// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"sync/atomic"
)

// ScrambledKey holds an RSA private key and its scrambled modulus.
type ScrambledKey struct {
	PrivateKey *rsa.PrivateKey      // The RSA private key used for decryption
	Modulus    [RSAModulusSize]byte // The scrambled public modulus (N)
}

const (
	RSAKeyBits     = 1024 // RSA key size in bits
	RSAModulusSize = 128  // RSA modulus size in bytes (for 1024-bit key)
)

var (
	rsaPool []ScrambledKey
	rsaIdx  atomic.Uint32
)

// InitRSAPool initializes a pool of pre-generated RSA keys to avoid expensive generation during login.
func InitRSAPool(size int) {
	if size <= 0 {
		panic("crypto: rsa pool size must be > 0")
	}

	rsaPool = make([]ScrambledKey, size)

	for i := 0; i < size; i++ {
		key, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
		if err != nil {
			panic(err)
		}

		// Ensure Precomputed values are generated for CRT optimization
		key.Precompute()

		var mod [RSAModulusSize]byte
		// Pass a copy of N to protect the original key structure
		nCopy := new(big.Int).Set(key.PublicKey.N)
		fillAndScrambleModulus(&mod, nCopy)

		rsaPool[i] = ScrambledKey{
			PrivateKey: key,
			Modulus:    mod,
		}
	}
}

// GetScrambledKey returns a pointer to a ScrambledKey using round-robin selection.
func GetScrambledKey() (*ScrambledKey, error) {
	poolLen := len(rsaPool)
	if poolLen == 0 {
		return nil, errors.New("crypto: rsa pool is not initialized")
	}

	i := rsaIdx.Add(1)
	return &rsaPool[uint(i)%uint(poolLen)], nil
}

// RSADecrypt decrypts the ciphertext using CRT optimization and guards against DoS.
func RSADecrypt(key *ScrambledKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != RSAModulusSize {
		return nil, errors.New("crypto: invalid ciphertext size")
	}

	c := new(big.Int).SetBytes(ciphertext)
	priv := key.PrivateKey

	m1 := new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
	m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])

	h := new(big.Int).Sub(m1, m2)
	if h.Sign() < 0 {
		h.Add(h, priv.Primes[0])
	}
	h.Mul(h, priv.Precomputed.Qinv)
	h.Mod(h, priv.Primes[0])

	m := new(big.Int).Mul(h, priv.Primes[1])
	m.Add(m, m2)

	plain := m.Bytes()

	if len(plain) < RSAModulusSize {
		padded := make([]byte, RSAModulusSize)
		copy(padded[RSAModulusSize-len(plain):], plain) // Pad with leading zeros
		return padded, nil
	}

	return plain, nil
}

func fillAndScrambleModulus(dst *[RSAModulusSize]byte, modulus *big.Int) {
	modulus.FillBytes(dst[:])

	// Swap 4 bytes at index 0 with 4 bytes at index 77
	for i := 0; i < 4; i++ {
		dst[i], dst[77+i] = dst[77+i], dst[i]
	}

	// XOR the first 64 bytes with the last 64 bytes
	for i := 0; i < 64; i++ {
		dst[i] ^= dst[64+i]
	}

	// XOR 4 bytes at index 13 with 4 bytes at index 52
	for i := 0; i < 4; i++ {
		dst[13+i] ^= dst[52+i]
	}

	// XOR the last 64 bytes with the first 64 bytes
	for i := 0; i < 64; i++ {
		dst[64+i] ^= dst[i]
	}
}
