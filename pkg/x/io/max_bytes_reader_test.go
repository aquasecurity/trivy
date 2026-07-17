package io_test

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) {
	return f(p)
}

func TestMaxBytesReader(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		limit     int64
		want      string
		wantError bool
		wantLimit int64
	}{
		{name: "empty input at zero limit", limit: 0},
		{name: "input below limit", input: "abc", limit: 4, want: "abc"},
		{name: "input exactly at limit", input: "abc", limit: 3, want: "abc"},
		{name: "input one byte over limit", input: "abcd", limit: 3, want: "abc", wantError: true, wantLimit: 3},
		{name: "non-empty input at zero limit", input: "a", wantError: true, wantLimit: 0},
		{name: "negative limit is zero", input: "a", limit: -1, wantError: true, wantLimit: 0},
		{name: "maximum limit", input: "abc", limit: math.MaxInt64, want: "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := io.ReadAll(xio.MaxBytesReader(strings.NewReader(tt.input), tt.limit))
			assert.Equal(t, tt.want, string(got))
			if !tt.wantError {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, xio.ErrLimitExceeded)
			assert.Equal(t, xio.ErrLimitExceeded.Error(), err.Error())

			wrapped := fmt.Errorf("read input: %w", err)
			require.ErrorIs(t, wrapped, xio.ErrLimitExceeded)
			var maxErr *xio.MaxBytesError
			require.ErrorAs(t, wrapped, &maxErr)
			assert.Equal(t, tt.wantLimit, maxErr.Limit)
		})
	}
}

func TestMaxBytesReaderMultipleReads(t *testing.T) {
	r := xio.MaxBytesReader(strings.NewReader("abcd"), 3)
	buf := make([]byte, 2)

	n, err := r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, "ab", string(buf[:n]))

	n, err = r.Read(buf)
	require.ErrorIs(t, err, xio.ErrLimitExceeded)
	assert.Equal(t, 1, n)
	assert.Equal(t, "c", string(buf[:n]))
	limitErr := err

	n, err = r.Read(buf)
	assert.Equal(t, 0, n)
	assert.Same(t, limitErr, err)
}

func TestMaxBytesReaderUnderlyingError(t *testing.T) {
	sourceErr := errors.New("source error")
	reads := 0
	r := xio.MaxBytesReader(readerFunc(func(p []byte) (int, error) {
		reads++
		return copy(p, "ab"), sourceErr
	}), 3)
	buf := make([]byte, 4)

	n, err := r.Read(buf)
	assert.Equal(t, 2, n)
	assert.Equal(t, "ab", string(buf[:n]))
	assert.Same(t, sourceErr, err)

	n, err = r.Read(buf)
	assert.Equal(t, 0, n)
	assert.Same(t, sourceErr, err)
	assert.Equal(t, 1, reads)
}

func TestMaxBytesReaderOverflowTakesPrecedence(t *testing.T) {
	sourceErr := errors.New("source error")
	r := xio.MaxBytesReader(readerFunc(func(p []byte) (int, error) {
		return copy(p, "abcd"), sourceErr
	}), 3)
	buf := make([]byte, 8)

	n, err := r.Read(buf)
	assert.Equal(t, 3, n)
	assert.Equal(t, "abc", string(buf[:n]))
	require.ErrorIs(t, err, xio.ErrLimitExceeded)
	assert.NotErrorIs(t, err, sourceErr)
}

func TestMaxBytesReaderReadBound(t *testing.T) {
	source := xio.NewCountingReader(strings.NewReader("abcdef"))
	r := xio.MaxBytesReader(source, 3)

	got, err := io.ReadAll(r)
	assert.Equal(t, "abc", string(got))
	require.ErrorIs(t, err, xio.ErrLimitExceeded)
	assert.Equal(t, int64(4), source.BytesRead())
	limitErr := err

	buf := make([]byte, 1)
	n, err := r.Read(buf)
	assert.Equal(t, 0, n)
	assert.Same(t, limitErr, err)
	assert.Equal(t, int64(4), source.BytesRead())
}

func TestMaxBytesReaderZeroLengthRead(t *testing.T) {
	source := xio.NewCountingReader(strings.NewReader("a"))
	r := xio.MaxBytesReader(source, -1)

	n, err := r.Read(nil)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, int64(0), source.BytesRead())
}
