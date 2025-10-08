package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Equals(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name: "equals with nil",
			args: []any{
				nil,
			},
			expected: false,
		},
		{
			name: "equals with nil and string",
			args: []any{
				nil,
				"test",
			},
			expected: false,
		},
		{
			name: "equals with nil and string and int",
			args: []any{
				nil,
				"test",
				1,
			},
			expected: false,
		},
		{
			name: "equals with nil and nil and array",
			args: []any{
				nil,
				nil,
				[]any{"a", "b", "c"},
			},
			expected: false,
		},
		{
			name: "equals with nil and nil",
			args: []any{
				nil,
				nil,
			},
			expected: true,
		},
		{
			name: "equals with string and string",
			args: []any{
				"test",
				"test",
			},
			expected: true,
		},
		{
			name: "equals with string and string",
			args: []any{
				"test",
				"test1",
			},
			expected: false,
		},
		{
			name: "equals with int and int",
			args: []any{
				1,
				1,
			},
			expected: true,
		},
		{
			name: "equals with int and int",
			args: []any{
				1,
				2,
			},
			expected: false,
		},
		{
			name: "equals with array and array",
			args: []any{
				[]any{"a", "b", "c"},
				[]any{"a", "b", "c"},
			},
			expected: true,
		},
		{
			name: "equals with array and array",
			args: []any{
				[]any{"a", "b", "c"},
				[]any{"a", "b", "d"},
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Equals(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
