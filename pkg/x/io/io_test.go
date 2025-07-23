package io

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopy(t *testing.T) {
	t.Run("successful copy", func(t *testing.T) {
		ctx := context.Background()
		src := strings.NewReader("hello world")
		dst := &bytes.Buffer{}

		n, err := Copy(ctx, dst, src)
		require.NoError(t, err)
		assert.Equal(t, int64(11), n)
		assert.Equal(t, "hello world", dst.String())
	})

	t.Run("context canceled before read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		src := strings.NewReader("hello world")
		dst := &bytes.Buffer{}

		n, err := Copy(ctx, dst, src)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, int64(0), n)
		assert.Empty(t, dst.String())
	})

	t.Run("context canceled during read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		// Create a reader that will be canceled after first read
		reader := &dummyReader{
			cancel: cancel, // Cancel after first read
		}
		dst := &bytes.Buffer{}

		n, err := Copy(ctx, dst, reader)
		assert.ErrorIs(t, err, context.Canceled)
		// Should have written first chunk before cancellation
		assert.Equal(t, int64(5), n)
		assert.Equal(t, "dummy", dst.String())
	})
}

// dummyReader returns the same data on every Read call
type dummyReader struct {
	cancel context.CancelFunc
}

func (r *dummyReader) Read(p []byte) (int, error) {
	n := copy(p, "dummy")
	if r.cancel != nil {
		r.cancel() // Simulate cancellation after first read
	}
	return n, nil
}
