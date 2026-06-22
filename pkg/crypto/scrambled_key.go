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
	"sync"
	"sync/atomic"
)

const (
	RSAKeyBits     = 1024 // RSA key size in bits
	RSAModulusSize = 128  // RSA modulus size in bytes (for 1024-bit key)
)

// ScrambledKey holds an RSA private key and its scrambled modulus.
type ScrambledKey struct {
	PrivateKey *rsa.PrivateKey      // The RSA private key used for decryption
	Modulus    [RSAModulusSize]byte // The scrambled public modulus (N)
}

// rsaScratch holds the big.Int temporaries for one CRT decryption.
type rsaScratch struct {
	c, m1, m2, h, m big.Int
}

var (
	rsaPool []ScrambledKey
	rsaIdx  atomic.Uint32
)

var rsaScratchPool = sync.Pool{New: func() any { return new(rsaScratch) }}

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

	priv := key.PrivateKey
	s := rsaScratchPool.Get().(*rsaScratch)

	s.c.SetBytes(ciphertext)

	s.m1.Exp(&s.c, priv.Precomputed.Dp, priv.Primes[0])
	s.m2.Exp(&s.c, priv.Precomputed.Dq, priv.Primes[1])

	s.h.Sub(&s.m1, &s.m2)
	if s.h.Sign() < 0 {
		s.h.Add(&s.h, priv.Primes[0])
	}
	s.h.Mul(&s.h, priv.Precomputed.Qinv)
	s.h.Mod(&s.h, priv.Primes[0])

	s.m.Mul(&s.h, priv.Primes[1])
	s.m.Add(&s.m, &s.m2)

	out := make([]byte, RSAModulusSize)
	s.m.FillBytes(out) // Always left-pads to 128 bytes; m < N (1024-bit) so it fits

	rsaScratchPool.Put(s)
	return out, nil
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
