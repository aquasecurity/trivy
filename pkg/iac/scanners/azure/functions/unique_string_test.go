package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_UniqueString(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "unique string from a string",
			args: []interface{}{
				"hello",
			},
			expected: "68656c6c6fe3b",
		},
		{
			name: "unique string from a string",
			args: []interface{}{
				"hello",
				"world",
			},
			expected: "68656c6c6f776",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := UniqueString(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
