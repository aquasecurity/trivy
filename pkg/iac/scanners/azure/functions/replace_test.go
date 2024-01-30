package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Replace(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "replace a string",
			args: []interface{}{
				"hello",
				"l",
				"p",
			},
			expected: "heppo",
		},
		{
			name: "replace a string with invalid replacement",
			args: []interface{}{
				"hello",
				"q",
				"p",
			},
			expected: "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Replace(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
