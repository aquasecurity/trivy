package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Coalesce(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name: "coalesce with nil",
			args: []any{
				nil,
			},
			expected: nil,
		},
		{
			name: "coalesce with nil and string",
			args: []any{
				nil,
				"test",
			},
			expected: "test",
		},
		{
			name: "coalesce with nil and string and int",
			args: []any{
				nil,
				"test",
				1,
			},
			expected: "test",
		},
		{
			name: "coalesce with nil and nil and array",
			args: []any{
				nil,
				nil,
				[]any{"a", "b", "c"},
			},
			expected: []any{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Coalesce(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
