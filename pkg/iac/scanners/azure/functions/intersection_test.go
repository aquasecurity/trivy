package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Intersect(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name: "intersect two arrays",
			args: []any{
				[]any{"a", "b", "c"},
				[]any{"b", "c", "d"},
			},
			expected: []any{"b", "c"},
		},
		{
			name: "intersect three arrays",
			args: []any{
				[]any{"a", "b", "c", "d"},
				[]any{"b", "c", "d"},
				[]any{"b", "c"},
			},
			expected: []any{"b", "c"},
		},
		{
			name: "intersect two arrays with one empty",
			args: []any{
				[]any{"a", "b", "c"},
				[]any{},
			},
			expected: []any(nil),
		},
		{
			name: "intersect two arrays with both empty",
			args: []any{
				[]any{},
				[]any{},
			},
			expected: []any(nil),
		},
		{
			name: "intersect two arrays with both nil",
			args: []any{
				nil,
				nil,
			},
			expected: []any{},
		},
		{
			name: "intersect two maps",
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
				"b": "b",
				"c": "c",
			},
		},
		{
			name: "intersect three maps",
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
					"d": "d",
				},
			},
			expected: map[string]any{
				"b": "b",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Intersection(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
