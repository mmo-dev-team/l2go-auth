// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"math/big"
	"testing"
)

// rsaDecryptOld reproduces the pre-fix decrypt: a fresh big.Int per temporary
// (~5 allocations) plus a conditional padding allocation.
func rsaDecryptOld(key *ScrambledKey, ciphertext []byte) []byte {
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
		copy(padded[RSAModulusSize-len(plain):], plain)
		return padded
	}
	return plain
}

func benchCiphertext(b *testing.B) (*ScrambledKey, []byte) {
	b.Helper()
	InitRSAPool(1)
	key, err := GetScrambledKey()
	if err != nil {
		b.Fatal(err)
	}
	// Build a valid ciphertext: c = m^e mod N for an arbitrary m < N.
	m := big.NewInt(0xDEADBEEFCAFE)
	e := big.NewInt(int64(key.PrivateKey.PublicKey.E))
	c := new(big.Int).Exp(m, e, key.PrivateKey.PublicKey.N)
	ct := make([]byte, RSAModulusSize)
	c.FillBytes(ct)
	return key, ct
}

func BenchmarkRSADecrypt_New(b *testing.B) {
	key, ct := benchCiphertext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RSADecrypt(key, ct)
	}
}

func BenchmarkRSADecrypt_Old(b *testing.B) {
	key, ct := benchCiphertext(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rsaDecryptOld(key, ct)
	}
}
