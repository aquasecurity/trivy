package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Less(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected any
	}{

		{
			name: "less with nil and string",
			args: []any{
				nil,
				"test",
			},
			expected: false,
		},
		{
			name: "less with nil and nil",
			args: []any{
				nil,
				nil,
			},
			expected: false,
		},
		{
			name: "less with string and string",
			args: []any{
				"test",
				"test",
			},
			expected: false,
		},
		{
			name: "less with string and int",
			args: []any{
				"test",
				1,
			},
			expected: false,
		},
		{
			name: "less with int and int",
			args: []any{
				1,
				1,
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Less(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func Test_LessThanOrEqual(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected any
	}{

		{
			name: "less with nil and string",
			args: []any{
				nil,
				"test",
			},
			expected: false,
		},
		{
			name: "less with nil and nil",
			args: []any{
				nil,
				nil,
			},
			expected: true,
		},
		{
			name: "less with string and string",
			args: []any{
				"test",
				"test",
			},
			expected: true,
		},
		{
			name: "less with string and int",
			args: []any{
				"test",
				1,
			},
			expected: false,
		},
		{
			name: "less with int and int",
			args: []any{
				1,
				1,
			},
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := LessOrEquals(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
