// Package buffer provides a very thin wrapper around []byte buffer called
// `Buffer`, to provide functionalities that are often used within the jwx
// related packages
package buffer

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/pkg/errors"
)

// Buffer wraps `[]byte` and provides functions that are often used in
// the jwx related packages. One notable difference is that while
// encoding/json marshalls `[]byte` using base64.StdEncoding, this
// module uses base64.RawURLEncoding as mandated by the spec
type Buffer []byte

// FromUint creates a `Buffer` from an unsigned int
func FromUint(v uint64) Buffer {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, v)

	i := 0
	for ; i < len(data); i++ {
		if data[i] != 0x0 {
			break
		}
	}
	return Buffer(data[i:])
}

// FromBase64 constructs a new Buffer from a base64 encoded data
func FromBase64(v []byte) (Buffer, error) {
	b := Buffer{}
	if err := b.Base64Decode(v); err != nil {
		return Buffer(nil), errors.Wrap(err, "failed to decode from base64")
	}

	return b, nil
}

// FromNData constructs a new Buffer from a "n:data" format
// (I made that name up)
func FromNData(v []byte) (Buffer, error) {
	size := binary.BigEndian.Uint32(v)
	buf := make([]byte, int(size))
	copy(buf, v[4:4+size])
	return Buffer(buf), nil
}

// Bytes returns the raw bytes that comprises the Buffer
func (b Buffer) Bytes() []byte {
	return []byte(b)
}

// NData returns Datalen || Data, where Datalen is a 32 bit counter for
// the length of the following data, and Data is the octets that comprise
// the buffer data
func (b Buffer) NData() []byte {
	buf := make([]byte, 4+b.Len())
	binary.BigEndian.PutUint32(buf, uint32(b.Len()))

	copy(buf[4:], b.Bytes())
	return buf
}

// Len returns the number of bytes that the Buffer holds
func (b Buffer) Len() int {
	return len(b)
}

// Base64Encode encodes the contents of the Buffer using base64.RawURLEncoding
func (b Buffer) Base64Encode() ([]byte, error) {
	enc := base64.RawURLEncoding
	out := make([]byte, enc.EncodedLen(len(b)))
	enc.Encode(out, b)
	return out, nil
}

// Base64Decode decodes the contents of the Buffer using base64.RawURLEncoding
func (b *Buffer) Base64Decode(v []byte) error {
	enc := base64.RawURLEncoding
	out := make([]byte, enc.DecodedLen(len(v)))
	n, err := enc.Decode(out, v)
	if err != nil {
		return errors.Wrap(err, "failed to decode from base64")
	}
	out = out[:n]
	*b = Buffer(out)
	return nil
}

// MarshalJSON marshals the buffer into JSON format after encoding the buffer
// with base64.RawURLEncoding
func (b Buffer) MarshalJSON() ([]byte, error) {
	v, err := b.Base64Encode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode to base64")
	}
	return json.Marshal(string(v))
}

// UnmarshalJSON unmarshals from a JSON string into a Buffer, after decoding it
// with base64.RawURLEncoding
func (b *Buffer) UnmarshalJSON(data []byte) error {
	var x string
	if err := json.Unmarshal(data, &x); err != nil {
		return errors.Wrap(err, "failed to unmarshal JSON")
	}
	return b.Base64Decode([]byte(x))
}
