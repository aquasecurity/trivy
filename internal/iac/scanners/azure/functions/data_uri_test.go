package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_data_uri_from_string(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{
			name: "data uri from string",
			args: []any{
				"Hello",
			},
			expected: "data:text/plain;charset=utf8;base64,SGVsbG8=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataUri := DataUri(tt.args...)
			require.Equal(t, tt.expected, dataUri)
		})
	}
}

func Test_string_from_data_uri(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{
			name: "data uri to string",
			args: []any{
				"data:;base64,SGVsbG8sIFdvcmxkIQ==",
			},
			expected: "Hello, World!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataUri := DataUriToString(tt.args...)
			require.Equal(t, tt.expected, dataUri)
		})
	}
}
