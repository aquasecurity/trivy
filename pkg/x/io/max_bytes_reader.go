package io

import (
	"errors"
	"fmt"
	"io"
)

// ErrLimitExceeded identifies reads that exceed a configured byte limit.
var ErrLimitExceeded = errors.New("io: read limit exceeded")

// MaxBytesError is returned by MaxBytesReader when its read limit is exceeded.
type MaxBytesError struct {
	Limit int64
}

func (e *MaxBytesError) Error() string {
	return fmt.Sprintf("%s: %d-byte limit", ErrLimitExceeded, e.Limit)
}

func (*MaxBytesError) Is(target error) bool {
	return target == ErrLimitExceeded
}

// MaxBytesReader returns a reader that exposes at most n bytes from r. It
// returns a MaxBytesError when a read proves that r contains more than n bytes.
// Detecting overflow consumes one byte beyond the limit from r.
// A negative limit is treated as zero.
func MaxBytesReader(r io.Reader, n int64) io.Reader {
	if n < 0 {
		n = 0
	}
	return &maxBytesReader{
		r:         r,
		limit:     n,
		remaining: n,
	}
}

type maxBytesReader struct {
	r         io.Reader
	limit     int64
	remaining int64
	err       error
}

func (r *maxBytesReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p))-1 > r.remaining {
		p = p[:r.remaining+1]
	}

	n, err := r.r.Read(p)
	if int64(n) <= r.remaining {
		r.remaining -= int64(n)
		r.err = err
		return n, err
	}

	// The overflow branch guarantees r.remaining < int64(n), so converting
	// r.remaining to int is safe.
	n = int(r.remaining)
	r.remaining = 0
	r.err = &MaxBytesError{Limit: r.limit}
	return n, r.err
}
