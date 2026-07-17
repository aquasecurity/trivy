package io

import "io"

// ReadAllWithLimit reads from r until EOF or until the read exceeds n bytes.
// On overflow, it returns the first n bytes and a MaxBytesError.
// A negative limit is treated as zero.
func ReadAllWithLimit(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(MaxBytesReader(r, n))
}
