// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"math/big"
	"testing"
)

// TestRSADecrypt_RoundTrip verifies the CRT decrypt with the pooled scratch
// big.Ints recovers the original message m from c = m^e mod N.
func TestRSADecrypt_RoundTrip(t *testing.T) {
	InitRSAPool(1)
	key, err := GetScrambledKey()
	if err != nil {
		t.Fatalf("GetScrambledKey: %v", err)
	}

	m := big.NewInt(0xDEADBEEFCAFE)
	e := big.NewInt(int64(key.PrivateKey.PublicKey.E))
	c := new(big.Int).Exp(m, e, key.PrivateKey.PublicKey.N)

	ct := make([]byte, RSAModulusSize)
	c.FillBytes(ct)

	out, err := RSADecrypt(key, ct)
	if err != nil {
		t.Fatalf("RSADecrypt: %v", err)
	}
	if len(out) != RSAModulusSize {
		t.Fatalf("expected %d-byte output, got %d", RSAModulusSize, len(out))
	}

	recovered := new(big.Int).SetBytes(out)
	if recovered.Cmp(m) != 0 {
		t.Fatalf("round-trip mismatch: got %x, want %x", recovered, m)
	}
}

// TestRSADecrypt_InvalidSize rejects ciphertext that is not exactly the modulus size.
func TestRSADecrypt_InvalidSize(t *testing.T) {
	InitRSAPool(1)
	key, err := GetScrambledKey()
	if err != nil {
		t.Fatalf("GetScrambledKey: %v", err)
	}

	if _, err := RSADecrypt(key, make([]byte, RSAModulusSize-1)); err == nil {
		t.Error("expected error for undersized ciphertext")
	}
	if _, err := RSADecrypt(key, make([]byte, RSAModulusSize+1)); err == nil {
		t.Error("expected error for oversized ciphertext")
	}
}

// TestGetScrambledKey_RoundRobin confirms consecutive picks rotate across the pool.
func TestGetScrambledKey_RoundRobin(t *testing.T) {
	InitRSAPool(2)
	first, err := GetScrambledKey()
	if err != nil {
		t.Fatalf("GetScrambledKey: %v", err)
	}
	second, err := GetScrambledKey()
	if err != nil {
		t.Fatalf("GetScrambledKey: %v", err)
	}
	if first == second {
		t.Error("expected round-robin to hand out distinct keys for a pool of 2")
	}
}
