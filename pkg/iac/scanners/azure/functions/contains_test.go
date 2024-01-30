package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Contains(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected bool
	}{
		{
			name: "simple true string contains",
			args: []interface{}{
				"hello, world",
				"hell",
			},
			expected: true,
		},
		{
			name: "simple false string contains",
			args: []interface{}{
				"hello, world",
				"help",
			},
			expected: false,
		},
		{
			name: "simple true string contains with case sensitivity",
			args: []interface{}{
				"hello, world",
				"HELL",
			},
			expected: true,
		},
		{
			name: "simple true string contains with number",
			args: []interface{}{
				"You're my number 1",
				1,
			},
			expected: true,
		},
		{
			name: "true object contains key",
			args: []interface{}{
				map[string]interface{}{
					"hello": "world",
				},
				"hello",
			},
			expected: true,
		},
		{
			name: "false object contains key",
			args: []interface{}{
				map[string]interface{}{
					"hello": "world",
				},
				"world",
			},
			expected: false,
		},
		{
			name: "true array contains value",
			args: []interface{}{
				[]interface{}{
					"hello", "world",
				},
				"hello",
			},
			expected: true,
		},
		{
			name: "false array contains value",
			args: []interface{}{
				[]interface{}{
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
