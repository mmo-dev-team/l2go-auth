// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package network

import (
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"unicode/utf16"
)

// PacketReader provides methods for reading various data types from a byte buffer.
type PacketReader struct {
	buf []byte
	pos int
}

const (
	MaxPacketSize = 65536 // Maximum allowed size for a single packet (64KB)
	MinPacketSize = 0     // Minimum allowed size for a single packet
)

var packetReaderPool = sync.Pool{
	New: func() any {
		return &PacketReader{}
	},
}

var decodePool = sync.Pool{
	New: func() any {
		b := make([]uint16, 1024)
		return &b
	},
}

// GetPacketReader retrieves a PacketReader from the pool and initializes it with the given data.
func GetPacketReader(data []byte) (*PacketReader, error) {
	if len(data) < MinPacketSize || len(data) > MaxPacketSize {
		return nil, errors.New("packet: invalid size")
	}

	r := packetReaderPool.Get().(*PacketReader)
	r.buf = data
	r.pos = 0
	return r, nil
}

// PutPacketReader clears the PacketReader and returns it to the pool.
func PutPacketReader(r *PacketReader) {
	r.buf = nil
	r.pos = 0
	packetReaderPool.Put(r)
}

// ReadableBytes returns the number of bytes remaining to be read from the buffer.
func (r *PacketReader) ReadableBytes() int {
	return len(r.buf) - r.pos
}

// ReadByte reads a single byte from the buffer.
func (r *PacketReader) ReadByte() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, errors.New("packet: out of bounds")
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

// ReadUint16 reads a 16-bit unsigned integer in little-endian format.
func (r *PacketReader) ReadUint16() (uint16, error) {
	if r.pos+2 > len(r.buf) {
		return 0, errors.New("packet: out of bounds")
	}
	v := binary.LittleEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, nil
}

// ReadUint32 reads a 32-bit unsigned integer in little-endian format.
func (r *PacketReader) ReadUint32() (uint32, error) {
	if r.pos+4 > len(r.buf) {
		return 0, errors.New("packet: out of bounds")
	}
	v := binary.LittleEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

// ReadUint64 reads a 64-bit unsigned integer in little-endian format.
func (r *PacketReader) ReadUint64() (uint64, error) {
	if r.pos+8 > len(r.buf) {
		return 0, errors.New("packet: out of bounds")
	}
	v := binary.LittleEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

// ReadInt16 reads a 16-bit signed integer in little-endian format.
func (r *PacketReader) ReadInt16() (int16, error) {
	v, err := r.ReadUint16()
	return int16(v), err
}

// ReadInt32 reads a 32-bit signed integer in little-endian format.
func (r *PacketReader) ReadInt32() (int32, error) {
	v, err := r.ReadUint32()
	return int32(v), err
}

// ReadInt64 reads a 64-bit signed integer in little-endian format.
func (r *PacketReader) ReadInt64() (int64, error) {
	v, err := r.ReadUint64()
	return int64(v), err
}

// ReadFloat32 reads a 32-bit floating point number in little-endian format.
func (r *PacketReader) ReadFloat32() (float32, error) {
	u, err := r.ReadUint32()
	if err != nil {
		return 0, err
	}
	return math.Float32frombits(u), nil
}

// ReadFloat64 reads a 64-bit floating point number in little-endian format.
func (r *PacketReader) ReadFloat64() (float64, error) {
	u, err := r.ReadUint64()
	if err != nil {
		return 0, err
	}
	return math.Float64frombits(u), nil
}

// ReadBytes returns a slice pointing into the underlying buffer.
// The slice is valid until the PacketReader is released.
func (r *PacketReader) ReadBytes(n int) ([]byte, error) {
	if err := r.ensure(n); err != nil {
		return nil, err
	}
	b := r.buf[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

// ReadString reads a null-terminated UTF-16LE string from the buffer.
func (r *PacketReader) ReadString() (string, error) {
	remainder := r.buf[r.pos:]
	var targetIdx = -1

	for i := 0; i < len(remainder)-1; i += 2 {
		if remainder[i] == 0 && remainder[i+1] == 0 {
			targetIdx = i
			break
		}
	}

	if targetIdx == -1 {
		return "", errors.New("packet: missing null terminator for string")
	}

	raw := remainder[:targetIdx]
	r.pos += targetIdx + 2

	if len(raw) == 0 {
		return "", nil
	}

	u16len := len(raw) / 2

	var u16 []uint16
	var pBuf *[]uint16
	if u16len <= 1024 {
		pBuf = decodePool.Get().(*[]uint16)
		u16 = (*pBuf)[:u16len]
		defer decodePool.Put(pBuf)
	} else {
		u16 = make([]uint16, u16len)
	}

	for i := 0; i < u16len; i++ {
		u16[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}

	return string(utf16.Decode(u16)), nil
}

func (r *PacketReader) ensure(n int) error {
	if r.pos+n > len(r.buf) {
		return errors.New("packet: out of bounds")
	}
	return nil
}
