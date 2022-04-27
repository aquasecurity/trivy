// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package leb128 implements LEB128 integer encoding.
package leb128

import (
	"io"
)

// MustReadVarInt32 returns an int32 from r or panics.
func MustReadVarInt32(r io.Reader) int32 {
	i32, err := ReadVarInt32(r)
	if err != nil {
		panic(err)
	}
	return i32
}

// MustReadVarInt64 returns an int64 from r or panics.
func MustReadVarInt64(r io.Reader) int64 {
	i64, err := ReadVarInt64(r)
	if err != nil {
		panic(err)
	}
	return i64
}

// MustReadVarUint32 returns an uint32 from r or panics.
func MustReadVarUint32(r io.Reader) uint32 {
	u32, err := ReadVarUint32(r)
	if err != nil {
		panic(err)
	}
	return u32
}

// MustReadVarUint64 returns an uint64 from r or panics.
func MustReadVarUint64(r io.Reader) uint64 {
	u64, err := ReadVarUint64(r)
	if err != nil {
		panic(err)
	}
	return u64
}

// Copied rom http://dwarfstd.org/doc/Dwarf3.pdf.

// ReadVarUint32 tries to read a uint32 from r.
func ReadVarUint32(r io.Reader) (uint32, error) {
	u64, err := ReadVarUint64(r)
	if err != nil {
		return 0, err
	}
	return uint32(u64), nil
}

// ReadVarUint64 tries to read a uint64 from r.
func ReadVarUint64(r io.Reader) (uint64, error) {
	var result uint64
	var shift uint64
	buf := make([]byte, 1)
	for {
		if _, err := r.Read(buf); err != nil {
			return 0, err
		}
		v := uint64(buf[0])
		result |= (v & 0x7F) << shift
		if v&0x80 == 0 {
			return result, nil
		}
		shift += 7
	}

}

// ReadVarInt32 tries to read a int32 from r.
func ReadVarInt32(r io.Reader) (int32, error) {
	i64, err := ReadVarInt64(r)
	if err != nil {
		return 0, err
	}
	return int32(i64), nil
}

// ReadVarInt64 tries to read a int64 from r.
func ReadVarInt64(r io.Reader) (int64, error) {
	var result int64
	var shift uint64
	size := uint64(32)
	buf := make([]byte, 1)
	for {
		if _, err := r.Read(buf); err != nil {
			return 0, err
		}
		v := int64(buf[0])
		result |= (v & 0x7F) << shift
		shift += 7
		if v&0x80 == 0 {
			if (shift < size) && (v&0x40 != 0) {
				result |= (^0 << shift)
			}
			return result, nil
		}
	}
}

// WriteVarUint32 writes u to w.
func WriteVarUint32(w io.Writer, u uint32) error {
	var b []byte
	_, err := w.Write(appendUleb128(b, uint64(u)))
	return err
}

// WriteVarUint64 writes u to w.
func WriteVarUint64(w io.Writer, u uint64) error {
	var b []byte
	_, err := w.Write(appendUleb128(b, u))
	return err
}

// WriteVarInt32 writes u to w.
func WriteVarInt32(w io.Writer, i int32) error {
	var b []byte
	_, err := w.Write(appendSleb128(b, int64(i)))
	return err
}

// WriteVarInt64 writes u to w.
func WriteVarInt64(w io.Writer, i int64) error {
	var b []byte
	_, err := w.Write(appendSleb128(b, i))
	return err
}

// Copied from https://github.com/golang/go/blob/master/src/cmd/internal/dwarf/dwarf.go.

// appendUleb128 appends v to b using DWARF's unsigned LEB128 encoding.
func appendUleb128(b []byte, v uint64) []byte {
	for {
		c := uint8(v & 0x7f)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		b = append(b, c)
		if c&0x80 == 0 {
			break
		}
	}
	return b
}

// appendSleb128 appends v to b using DWARF's signed LEB128 encoding.
func appendSleb128(b []byte, v int64) []byte {
	for {
		c := uint8(v & 0x7f)
		s := uint8(v & 0x40)
		v >>= 7
		if (v != -1 || s == 0) && (v != 0 || s != 0) {
			c |= 0x80
		}
		b = append(b, c)
		if c&0x80 == 0 {
			break
		}
	}
	return b
}
