package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_StringConcatenation(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{
			name: "simple string concatenation",
			args: []any{
				"hello",
				", ",
				"world",
				"!",
			},
			expected: "hello, world!",
		},
		{
			name: "string concatenation with non strings",
			args: []any{
				"pi to 3 decimal places is ",
				3.142,
			},
			expected: "pi to 3 decimal places is 3.142",
		},
		{
			name: "string concatenation with multiple primitives",
			args: []any{
				"to say that ",
				3,
				" is greater than ",
				5,
				" would be ",
				false,
			},
			expected: "to say that 3 is greater than 5 would be false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			concatenated := Concat(tt.args...)
			require.Equal(t, tt.expected, concatenated)
		})
	}
}

func Test_ArrayConcatenation(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected []any
	}{
		{
			name: "simple array concatenation",
			args: []any{
				[]any{1, 2, 3},
				[]any{4, 5, 6},
			},
			expected: []any{1, 2, 3, 4, 5, 6},
		},
		{
			name: "array concatenation with non arrays",
			args: []any{
				[]any{1, 2, 3},
				4,
			},
			expected: []any{1, 2, 3},
		},
		{
			name: "array concatenation with multiple primitives",
			args: []any{
				[]any{1, 2, 3},
				4,
				[]any{5, 6, 7},
			},
			expected: []any{1, 2, 3, 5, 6, 7},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			concatenated := Concat(tt.args...)
			require.Equal(t, tt.expected, concatenated)
		})
	}
}
