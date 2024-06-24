package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Take(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name: "take a string",
			args: []any{
				"hello",
				2,
			},
			expected: "he",
		},
		{
			name: "take a string with invalid count",
			args: []any{
				"hello",
				10,
			},
			expected: "hello",
		},
		{
			name: "take a string from slice",
			args: []any{
				[]string{"a", "b", "c"},
				2,
			},
			expected: []string{"a", "b"},
		},
		{
			name: "take a string from a slice",
			args: []any{
				[]string{"a", "b", "c"},
				2,
			},
			expected: []string{"a", "b"},
		},
		{
			name: "take a string from a slice with invalid count",
			args: []any{
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
