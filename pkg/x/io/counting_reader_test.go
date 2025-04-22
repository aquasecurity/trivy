package io

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCountingReader(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		readSize int
		want     int64
	}{
		{
			name:     "empty data",
			data:     []byte{},
			readSize: 10,
			want:     0,
		},
		{
			name:     "small data single read",
			data:     []byte("hello"),
			readSize: 10,
			want:     5,
		},
		{
			name:     "multiple reads",
			data:     []byte("hello world"),
			readSize: 5,
			want:     11,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a reader with test data
			reader := bytes.NewReader(tc.data)

			// Wrap with counter
			counter := NewCountingReader(reader)

			// Read all data
			buf := make([]byte, tc.readSize)
			for {
				n, err := counter.Read(buf)
				if err == io.EOF {
					break
				}
				assert.NoError(t, err, "unexpected error during read")
				if n == 0 {
					break
				}
			}

			// Verify bytes read
			assert.Equal(t, tc.want, counter.BytesRead(), "BytesRead() should return correct count")
		})
	}
}
