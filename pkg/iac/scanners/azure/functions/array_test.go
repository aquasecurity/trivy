package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Array(t *testing.T) {
	test := []struct {
		name     string
		input    []any
		expected any
	}{
		{
			name:     "array from an int",
			input:    []any{1},
			expected: []int{1},
		},
		{
			name:     "array from a string",
			input:    []any{"hello"},
			expected: []string{"hello"},
		},
		{
			name:     "array from a map",
			input:    []any{map[string]any{"hello": "world"}},
			expected: []any{"hello", "world"},
		},
		{
			name: "array from an slice",
			input: []any{
				[]string{"hello", "world"},
			},
			expected: []string{"hello", "world"},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			actual := Array(tt.input...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
