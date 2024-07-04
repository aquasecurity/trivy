package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CreateObject(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name:     "CreateObject with no args",
			args:     []any{},
			expected: make(map[string]any),
		},
		{
			name:     "CreateObject with one arg",
			args:     []any{"foo", "bar"},
			expected: map[string]any{"foo": "bar"},
		},
		{
			name:     "CreateObject with two args",
			args:     []any{"foo", "bar", "baz", "qux"},
			expected: map[string]any{"foo": "bar", "baz": "qux"},
		},
		{
			name:     "CreateObject with three args",
			args:     []any{"foo", "bar", "baz", 1, "quux", true},
			expected: map[string]any{"foo": "bar", "baz": 1, "quux": true},
		},
		{
			name:     "CreateObject with odd number of args",
			args:     []any{"foo", "bar", "baz"},
			expected: make(map[string]any),
		},
		{
			name: "CreateObject with odd number of args",
			args: []any{"foo", "bar", "baz", []string{"Hello", "World"}},
			expected: map[string]any{
				"foo": "bar",
				"baz": []string{
					"Hello", "World",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CreateObject(tt.args...)
			assert.Equal(t, tt.expected, got)
		})
	}

}
