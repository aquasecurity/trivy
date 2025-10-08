package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Skip(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name: "skip a string",
			args: []any{
				"hello",
				1,
			},
			expected: "ello",
		},
		{
			name: "skip beyond the length a string",
			args: []any{
				"hello",
				6,
			},
			expected: "",
		},
		{
			name: "skip with a zero count on a string",
			args: []any{
				"hello",
				0,
			},
			expected: "hello",
		},
		{
			name: "skip with slice of ints",
			args: []any{
				[]int{1, 2, 3, 4, 5},
				2,
			},
			expected: []int{3, 4, 5},
		},
		{
			name: "skip with slice of strings",
			args: []any{
				[]string{"hello", "world"},
				1,
			},
			expected: []string{"world"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Skip(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}
