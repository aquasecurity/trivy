package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IndexOf(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected int
	}{
		{
			name: "get index of string that is there",
			args: []interface{}{
				"Hello world!",
				"Hell",
			},
			expected: 0,
		},
		{
			name: "get index of string that is there as well",
			args: []interface{}{
				"Hello world!",
				"world",
			},
			expected: 6,
		},
		{
			name: "get index of string that isn't there",
			args: []interface{}{
				"Hello world!",
				"planet!",
			},
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := IndexOf(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
