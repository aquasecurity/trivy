package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Array(t *testing.T) {
	test := []struct {
		name     string
		input    []interface{}
		expected interface{}
	}{
		{
			name:     "array from an int",
			input:    []interface{}{1},
			expected: []int{1},
		},
		{
			name:     "array from a string",
			input:    []interface{}{"hello"},
			expected: []string{"hello"},
		},
		{
			name:     "array from a map",
			input:    []interface{}{map[string]interface{}{"hello": "world"}},
			expected: []interface{}{"hello", "world"},
		},
		{
			name: "array from an slice",
			input: []interface{}{
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
