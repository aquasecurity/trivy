package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_JSON(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected map[string]any
	}{
		{
			name: "simple json string to json type",
			args: []any{
				`{"hello": "world"}`,
			},
			expected: map[string]any{
				"hello": "world",
			},
		},
		{
			name: "more complex json string to json type",
			args: []any{
				`{"hello": ["world", "world2"]}`,
			},
			expected: map[string]any{
				"hello": []any{"world", "world2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := JSON(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
