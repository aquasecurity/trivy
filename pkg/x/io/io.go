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

func NewReadSeekerAtWithSize(r io.Reader) (ReadSeekerAt, int64, error) {
	rsa, err := NewReadSeekerAt(r)
	if err != nil {
		return nil, 0, err
	}

	br, ok := rsa.(*bytes.Reader)
	if ok {
		return rsa, br.Size(), nil
	}

	size, err := getSeekerSize(rsa)
	if err != nil {
		return nil, 0, xerrors.Errorf("get size error: %w", err)
	}
	return rsa, size, nil
}

func getSeekerSize(s io.Seeker) (int64, error) {
	size, err := s.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, xerrors.Errorf("seek error: %w", err)
	}

	if _, err = s.Seek(0, io.SeekStart); err != nil {
		return 0, xerrors.Errorf("seek error: %w", err)
	}
	return size, nil
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
