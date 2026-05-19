// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package network

import (
	"encoding/binary"
	"math"
	"sync"
	"unicode/utf16"
)

// PacketWriter provides methods for writing various data types to a byte buffer.
type PacketWriter struct {
	buf []byte
}

const defaultWriterCap = 1024 // Default initial capacity for the writer's buffer

var packetWriterPool = sync.Pool{
	New: func() any {
		return &PacketWriter{
			buf: make([]byte, 0, defaultWriterCap),
		}
	},
}

// GetPacketWriter retrieves a PacketWriter from the pool, resets its length,
// and pre-allocates the first 2 bytes to reserve space for the packet length.
func GetPacketWriter() *PacketWriter {
	w := packetWriterPool.Get().(*PacketWriter)
	w.reset()

	w.Reserve(2)
	w.buf = append(w.buf, 0, 0)
	return w
}

// PutPacketWriter clears the PacketWriter buffer and returns it to the pool.
func PutPacketWriter(w *PacketWriter) {
	if cap(w.buf) > 64*1024 {
		w.buf = nil
	} else {
		w.buf = w.buf[:0]
	}
	packetWriterPool.Put(w)
}

// PrependLength writes the current buffer length into the first 2 bytes of the buffer.
func (w *PacketWriter) PrependLength() {
	length := len(w.buf)
	if length > 65535 {
		panic("packet size exceeds max uint16 limit")
	}
	binary.LittleEndian.PutUint16(w.buf[0:2], uint16(length))
}

// Bytes returns the underlying byte slice.
func (w *PacketWriter) Bytes() []byte {
	return w.buf
}

// WriteByte writes a single byte to the buffer.
func (w *PacketWriter) WriteByte(v byte) {
	w.buf = append(w.buf, v)
}

// WriteUint16 writes a 16-bit unsigned integer in little-endian format.
func (w *PacketWriter) WriteUint16(v uint16) {
	pos := len(w.buf)
	w.buf = append(w.buf, 0, 0)
	binary.LittleEndian.PutUint16(w.buf[pos:], v)
}

// WriteInt16 writes a 16-bit signed integer in little-endian format.
func (w *PacketWriter) WriteInt16(v int16) {
	w.WriteUint16(uint16(v))
}

// WriteUint32 writes a 32-bit unsigned integer in little-endian format.
func (w *PacketWriter) WriteUint32(v uint32) {
	pos := len(w.buf)
	w.buf = append(w.buf, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(w.buf[pos:], v)
}

// WriteInt32 writes a 32-bit signed integer in little-endian format.
func (w *PacketWriter) WriteInt32(v int32) {
	w.WriteUint32(uint32(v))
}

// WriteUint64 writes a 64-bit unsigned integer in little-endian format.
func (w *PacketWriter) WriteUint64(v uint64) {
	pos := len(w.buf)
	w.buf = append(w.buf, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.LittleEndian.PutUint64(w.buf[pos:], v)
}

// WriteInt64 writes a 64-bit signed integer in little-endian format.
func (w *PacketWriter) WriteInt64(v int64) {
	w.WriteUint64(uint64(v))
}

// WriteFloat32 writes a 32-bit floating point number in little-endian format.
func (w *PacketWriter) WriteFloat32(v float32) {
	u := math.Float32bits(v)
	w.WriteUint32(u)
}

// WriteFloat64 writes a 64-bit floating point number in little-endian format.
func (w *PacketWriter) WriteFloat64(v float64) {
	u := math.Float64bits(v)
	w.WriteUint64(u)
}

// WriteBytes appends the given byte slice to the buffer.
func (w *PacketWriter) WriteBytes(b []byte) {
	w.buf = append(w.buf, b...)
}

// Extend increases buffer length by n bytes without initialization.
// Caller MUST fully overwrite the returned slice.
func (w *PacketWriter) Extend(n int) []byte {
	w.Reserve(n)
	l := len(w.buf)
	w.buf = w.buf[:l+n]
	return w.buf[l:]
}

// Reserve ensures the buffer has at least n bytes of additional capacity.
// It uses a growth strategy that minimizes allocations and avoids temporary slices.
func (w *PacketWriter) Reserve(n int) {
	if cap(w.buf)-len(w.buf) < n {
		newCap := (cap(w.buf) + n) * 2
		if newCap > 65536 {
			newCap = cap(w.buf) + n
		}
		newBuf := make([]byte, len(w.buf), newCap)
		copy(newBuf, w.buf)
		w.buf = newBuf
	}
}

// WriteString writes a null-terminated UTF-16LE string to the buffer.
func (w *PacketWriter) WriteString(s string) {
	utf16Count := utf16Len(s)
	sizeInBytes := (utf16Count * 2) + 2
	pos := len(w.buf)
	w.Reserve(sizeInBytes)
	w.buf = w.buf[:pos+sizeInBytes]

	for _, r := range s {
		if r <= 0xFFFF {
			binary.LittleEndian.PutUint16(w.buf[pos:pos+2], uint16(r))
			pos += 2
		} else {
			r1, r2 := utf16.EncodeRune(r)
			binary.LittleEndian.PutUint16(w.buf[pos:pos+2], uint16(r1))
			binary.LittleEndian.PutUint16(w.buf[pos+2:pos+4], uint16(r2))
			pos += 4
		}
	}

	binary.LittleEndian.PutUint16(w.buf[pos:], 0)
}

// WriteSizedString writes a string preceded by a short (16-bit) length.
// Unlike WriteString, this does NOT write a null terminator.
func (w *PacketWriter) WriteSizedString(s string) {
	utf16Count := utf16Len(s)
	w.WriteInt16(int16(utf16Count))
	sizeInBytes := utf16Count * 2
	pos := len(w.buf)
	w.Reserve(sizeInBytes)
	w.buf = w.buf[:pos+sizeInBytes]

	for _, r := range s {
		if r <= 0xFFFF {
			binary.LittleEndian.PutUint16(w.buf[pos:pos+2], uint16(r))
			pos += 2
		} else {
			r1, r2 := utf16.EncodeRune(r)
			binary.LittleEndian.PutUint16(w.buf[pos:pos+2], uint16(r1))
			binary.LittleEndian.PutUint16(w.buf[pos+2:pos+4], uint16(r2))
			pos += 4
		}
	}
}

// utf16Len returns the number of UTF-16 code units for a string.
// Characters outside the Basic Multilingual Plane (> 0xFFFF) require a surrogate pair (2 code units).
func utf16Len(s string) int {
	count := 0
	for _, r := range s {
		if r <= 0xFFFF {
			count++
		} else {
			count += 2
		}
	}
	return count
}

func (w *PacketWriter) reset() {
	w.buf = w.buf[:0]
}
