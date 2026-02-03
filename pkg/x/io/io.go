package io

import (
	"bytes"
	"context"
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

// readerFunc is a function that implements io.Reader
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) {
	return f(p)
}

// Copy copies from src to dst until either EOF is reached on src or the context is canceled.
// It returns the number of bytes copied and the first error encountered while copying, if any.
//
// Note: This implementation wraps the reader with a context check, which means it won't
// benefit from WriterTo optimization in io.Copy if the source implements it. This is a trade-off
// for being able to cancel the operation on context cancellation.
func Copy(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, readerFunc(func(p []byte) (int, error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
			return src.Read(p)
		}
	}))
}
