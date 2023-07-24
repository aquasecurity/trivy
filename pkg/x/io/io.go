package io

import "io"

// NopCloser returns a WriteCloser with a no-op Close method wrapping
// the provided Writer w.
func NopCloser(rw io.ReadWriter) io.ReadWriteCloser {
	return nopCloser{rw}
}

type nopCloser struct {
	io.ReadWriter
}

func (nopCloser) Close() error { return nil }
