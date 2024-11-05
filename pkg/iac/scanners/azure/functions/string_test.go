package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_String(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{
			name: "string from a string",
			args: []any{
				"hello",
			},
			expected: "hello",
		},
		{
			name: "string from a bool",
			args: []any{
				false,
			},
			expected: "false",
		},
		{
			name: "string from an int",
			args: []any{
				10,
			},
			expected: "10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := String(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
