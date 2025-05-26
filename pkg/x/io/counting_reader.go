package io

import (
	"io"
)

// CountingReader wraps an io.Reader and counts the number of bytes read.
// Note: This implementation is NOT thread-safe. It should not be used
// concurrently from multiple goroutines.
type CountingReader struct {
	r         io.Reader
	bytesRead int64
}

// NewCountingReader creates a new CountingReader that wraps the provided io.Reader.
func NewCountingReader(r io.Reader) *CountingReader {
	return &CountingReader{r: r}
}

// Read reads data from the underlying reader and counts the number of bytes read.
func (c *CountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.bytesRead += int64(n)
	}
	return n, err
}

// BytesRead returns the number of bytes read.
func (c *CountingReader) BytesRead() int64 {
	return c.bytesRead
}
