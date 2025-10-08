package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Guid(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{
			name: "guid from a string",
			args: []any{
				"hello",
			},
			expected: "2cf24dba-5fb0-430e-a6e8-3b2ac5b9e29e",
		},
		{
			name:     "guid from an string",
			args:     []any{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guid := Guid(tt.args...)
			require.Equal(t, tt.expected, guid)
		})
	}
}
