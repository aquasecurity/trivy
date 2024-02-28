package io

import (
	"bytes"
	"io"

	"golang.org/x/xerrors"
)

type ReadSeekerAt interface {
	io.ReadSeeker
	io.ReaderAt
}

type ReadSeekCloserAt interface {
	io.ReadSeekCloser
	io.ReaderAt
}

func NewReadSeekerAt(r io.Reader) (ReadSeekerAt, error) {
	if rr, ok := r.(ReadSeekerAt); ok {
		return rr, nil
	}

	buff := bytes.NewBuffer([]byte{})
	if _, err := io.Copy(buff, r); err != nil {
		return nil, xerrors.Errorf("copy error: %w", err)
	}

	return bytes.NewReader(buff.Bytes()), nil
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
