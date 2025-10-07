package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_LastIndexOf(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected int
	}{
		{
			name: "get last index of string that is there",
			args: []any{
				"Hello world!",
				"l",
			},
			expected: 9,
		},
		{
			name: "get last index of string that is there as well",
			args: []any{
				"Hello world!",
				"world",
			},
			expected: 6,
		},
		{
			name: "get last index of string that isn't there",
			args: []any{
				"Hello world!",
				"planet!",
			},
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := LastIndexOf(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
