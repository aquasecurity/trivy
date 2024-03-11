package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Skip(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name: "skip a string",
			args: []interface{}{
				"hello",
				1,
			},
			expected: "ello",
		},
		{
			name: "skip beyond the length a string",
			args: []interface{}{
				"hello",
				6,
			},
			expected: "",
		},
		{
			name: "skip with a zero count on a string",
			args: []interface{}{
				"hello",
				0,
			},
			expected: "hello",
		},
		{
			name: "skip with slice of ints",
			args: []interface{}{
				[]int{1, 2, 3, 4, 5},
				2,
			},
			expected: []int{3, 4, 5},
		},
		{
			name: "skip with slice of strings",
			args: []interface{}{
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
