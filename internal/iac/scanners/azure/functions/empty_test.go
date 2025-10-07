package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Empty(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected bool
	}{
		{
			name: "string is empty",
			args: []any{
				"",
			},
			expected: true,
		},
		{
			name: "string is not empty",
			args: []any{
				"hello, world",
			},
			expected: false,
		},
		{
			name: "array is empty",
			args: []any{
				[]string{},
			},
			expected: true,
		},
		{
			name: "array is not empty",
			args: []any{
				[]string{"Hello", "World"},
			},
			expected: false,
		},
		{
			name: "map is empty",
			args: []any{
				make(map[string]any),
			},
			expected: true,
		},
		{
			name: "map is not empty",
			args: []any{
				map[string]any{
					"hello": "world",
				},
				"world",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doesContain := Empty(tt.args...)
			require.Equal(t, tt.expected, doesContain)
		})
	}
}
