package io

import "io"

type ReadSeekerAt interface {
	io.ReadSeeker
	io.ReaderAt
}

type ReadSeekCloserAt interface {
	io.ReadSeekCloser
	io.ReaderAt
}

// NopCloser returns a ReadSeekCloserAt with a no-op Close method wrapping
// the provided Reader r.
func NopCloser(r ReadSeekerAt) ReadSeekCloserAt {
	return nopCloser{r}
}

type nopCloser struct {
	ReadSeekerAt
}

func (nopCloser) Close() error { return nil }
