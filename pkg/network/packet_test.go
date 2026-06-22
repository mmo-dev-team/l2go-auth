// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package network

import (
	"testing"
)

func TestPacketRoundTrip(t *testing.T) {
	w := GetPacketWriter()
	defer PutPacketWriter(w)

	w.WriteByte(0x42)
	w.WriteUint16(0x1234)
	w.WriteUint32(0x87654321)
	w.WriteFloat64(3.14159)
	w.WriteString("Hello, Lineage 2!")

	w.PrependLength()
	data := w.Bytes()

	if len(data) < 2 {
		t.Fatalf("Expected data length >= 2, got %d", len(data))
	}

	r, err := GetPacketReader(data)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}
	defer PutPacketReader(r)

	// First 2 bytes are length
	length, err := r.ReadUint16()
	if err != nil {
		t.Fatalf("Failed to read length: %v", err)
	}
	if int(length) != len(data) {
		t.Errorf("Expected length %d, got %d", len(data), length)
	}

	b, _ := r.ReadByte()
	if b != 0x42 {
		t.Errorf("Expected byte 0x42, got %x", b)
	}

	u16, _ := r.ReadUint16()
	if u16 != 0x1234 {
		t.Errorf("Expected uint16 0x1234, got %x", u16)
	}

	u32, _ := r.ReadUint32()
	if u32 != 0x87654321 {
		t.Errorf("Expected uint32 0x87654321, got %x", u32)
	}

	f64, _ := r.ReadFloat64()
	if f64 != 3.14159 {
		t.Errorf("Expected float64 3.14159, got %f", f64)
	}

	str, _ := r.ReadString()
	if str != "Hello, Lineage 2!" {
		t.Errorf("Expected string 'Hello, Lineage 2!', got '%s'", str)
	}
}

func TestPacketReaderBounds(t *testing.T) {
	data := []byte{0x01, 0x02}
	r, _ := GetPacketReader(data)
	defer PutPacketReader(r)

	_, err := r.ReadUint32()
	if err == nil {
		t.Error("Expected error when reading out of bounds")
	}
}

// TestSkipString advances past a UTF-16LE string without decoding it.
func TestSkipString(t *testing.T) {
	w := GetPacketWriter()
	defer PutPacketWriter(w)

	w.WriteString("skip-me")
	w.WriteByte(0xAB)
	data := w.Bytes()

	r, err := GetPacketReader(data)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}
	defer PutPacketReader(r)

	if _, err = r.ReadUint16(); err != nil { // consume the 2-byte length header
		t.Fatalf("ReadUint16 header: %v", err)
	}

	if err = r.SkipString(); err != nil {
		t.Fatalf("SkipString returned error: %v", err)
	}

	b, err := r.ReadByte()
	if err != nil {
		t.Fatalf("ReadByte after SkipString: %v", err)
	}
	if b != 0xAB {
		t.Errorf("Expected to land on 0xAB after skip, got 0x%X", b)
	}
}

func TestSkipStringMissingTerminator(t *testing.T) {
	r, err := GetPacketReader([]byte{0x41, 0x00, 0x42, 0x00})
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}
	defer PutPacketReader(r)

	if err = r.SkipString(); err == nil {
		t.Error("Expected error when no null terminator is present")
	}
}

func FuzzPacketReader(f *testing.F) {
	// Seed corpus with some semi-valid looking data
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00})
	f.Add([]byte{0x00, 0x01, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := GetPacketReader(data)
		if err != nil {
			return // Ignore invalid size errors from GetPacketReader
		}
		defer PutPacketReader(r)

		// Try to read various types. The goal is to NOT panic.
		// We don't care about the values, only that the reader handles bounds correctly.
		_, _ = r.ReadByte()
		_, _ = r.ReadUint16()
		_, _ = r.ReadUint32()
		_, _ = r.ReadUint64()
		_, _ = r.ReadFloat32()
		_, _ = r.ReadFloat64()
		_, _ = r.ReadString()
		_, _ = r.ReadBytes(len(data) / 2)
	})
}
