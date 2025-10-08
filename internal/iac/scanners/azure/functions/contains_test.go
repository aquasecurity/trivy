package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Contains(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected bool
	}{
		{
			name: "simple true string contains",
			args: []any{
				"hello, world",
				"hell",
			},
			expected: true,
		},
		{
			name: "simple false string contains",
			args: []any{
				"hello, world",
				"help",
			},
			expected: false,
		},
		{
			name: "simple true string contains with case sensitivity",
			args: []any{
				"hello, world",
				"HELL",
			},
			expected: true,
		},
		{
			name: "simple true string contains with number",
			args: []any{
				"You're my number 1",
				1,
			},
			expected: true,
		},
		{
			name: "true object contains key",
			args: []any{
				map[string]any{
					"hello": "world",
				},
				"hello",
			},
			expected: true,
		},
		{
			name: "false object contains key",
			args: []any{
				map[string]any{
					"hello": "world",
				},
				"world",
			},
			expected: false,
		},
		{
			name: "true array contains value",
			args: []any{
				[]any{
					"hello", "world",
				},
				"hello",
			},
			expected: true,
		},
		{
			name: "false array contains value",
			args: []any{
				[]any{
					"hello", "world",
				},
				"help",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doesContain := Contains(tt.args...)
			require.Equal(t, tt.expected, doesContain)
		})
	}
}
