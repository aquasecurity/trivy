package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CreateArray(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name: "create array with strings",
			args: []any{
				"Hello",
				"World",
			},
			expected: []any{"Hello", "World"},
		},
		{
			name: "create array with ints",

			args: []any{
				1, 2, 3,
			},
			expected: []any{1, 2, 3},
		},
		{
			name: "create array with arrays",
			args: []any{
				[]any{1, 2, 3},
				[]any{4, 5, 6},
			},
			expected: []any{[]any{1, 2, 3}, []any{4, 5, 6}},
		},
		{
			name: "create arrau with maps",
			args: []any{
				map[string]any{
					"one": "a",
				},
				map[string]any{
					"two": "b",
				},
			},
			expected: []any{
				map[string]any{
					"one": "a",
				},
				map[string]any{
					"two": "b",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := CreateArray(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}
