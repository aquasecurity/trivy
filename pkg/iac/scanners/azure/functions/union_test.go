package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Union(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name: "union single array",
			args: []any{
				[]any{"a", "b", "c"},
			},
			expected: []any{"a", "b", "c"},
		},
		{
			name: "union two arrays",
			args: []any{
				[]any{"a", "b", "c"},
				[]any{"b", "c", "d"},
			},
			expected: []any{"a", "b", "c", "d"},
		},
		{
			name: "union two arrays",
			args: []any{
				[]any{"a", "b", "c"},
				[]any{"b", "c", "d"},
				[]any{"b", "c", "d", "e"},
			},
			expected: []any{"a", "b", "c", "d", "e"},
		},
		{
			name: "union single maps",
			args: []any{
				map[string]any{
					"a": "a",
					"b": "b",
					"c": "c",
				},
			},
			expected: map[string]any{
				"a": "a",
				"b": "b",
				"c": "c",
			},
		},
		{
			name: "union two maps",
			args: []any{
				map[string]any{
					"a": "a",
					"b": "b",
					"c": "c",
				},
				map[string]any{
					"b": "b",
					"c": "c",
					"d": "d",
				},
			},
			expected: map[string]any{
				"a": "a",
				"b": "b",
				"c": "c",
				"d": "d",
			},
		},
		{
			name: "union three maps",
			args: []any{
				map[string]any{
					"a": "a",
					"b": "b",
					"c": "c",
				},
				map[string]any{
					"b": "b",
					"c": "c",
					"d": "d",
				},
				map[string]any{
					"b": "b",
					"c": "c",
					"e": "e",
				},
			},
			expected: map[string]any{
				"a": "a",
				"b": "b",
				"c": "c",
				"d": "d",
				"e": "e",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Union(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
