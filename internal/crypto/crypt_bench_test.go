// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"testing"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"
)

// BenchmarkEncryptStatic is the current per-accept Init encryption: a shared read-only Blowfish cipher.
func BenchmarkEncryptStatic(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := network.GetPacketWriter()
		buildInitPayload(w)
		EncryptStatic(w)
		network.PutPacketWriter(w)
	}
}

func buildInitPayload(w *network.PacketWriter) {
	w.WriteByte(0x00)
	w.WriteInt32(12345)
	w.WriteInt32(0x0000c621)
	var modulus [128]byte
	w.WriteBytes(modulus[:])
	w.WriteUint32(0x29DD954E)
	w.WriteUint32(0x77C39CFC)
	w.WriteUint32(0x97ADB620)
	w.WriteUint32(0x07BDE0F7)
	var secret [16]byte
	w.WriteBytes(secret[:])
	w.WriteByte(0x00)
}
