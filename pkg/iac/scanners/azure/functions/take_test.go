package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Take(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name: "take a string",
			args: []interface{}{
				"hello",
				2,
			},
			expected: "he",
		},
		{
			name: "take a string with invalid count",
			args: []interface{}{
				"hello",
				10,
			},
			expected: "hello",
		},
		{
			name: "take a string from slice",
			args: []interface{}{
				[]string{"a", "b", "c"},
				2,
			},
			expected: []string{"a", "b"},
		},
		{
			name: "take a string from a slice",
			args: []interface{}{
				[]string{"a", "b", "c"},
				2,
			},
			expected: []string{"a", "b"},
		},
		{
			name: "take a string from a slice with invalid count",
			args: []interface{}{
				[]string{"a", "b", "c"},
				10,
			},
			expected: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Take(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
