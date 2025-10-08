package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Greater(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected any
	}{

		{
			name: "greater with nil and string",
			args: []any{
				nil,
				"test",
			},
			expected: false,
		},
		{
			name: "greater with nil and nil",
			args: []any{
				nil,
				nil,
			},
			expected: false,
		},
		{
			name: "greater with string and string",
			args: []any{
				"test",
				"test",
			},
			expected: false,
		},
		{
			name: "greater with string and int",
			args: []any{
				"test",
				1,
			},
			expected: false,
		},
		{
			name: "greater with int and int",
			args: []any{
				1,
				1,
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Greater(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func Test_GreaterThanOrEqual(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected any
	}{

		{
			name: "greater with nil and string",
			args: []any{
				nil,
				"test",
			},
			expected: false,
		},
		{
			name: "greater with nil and nil",
			args: []any{
				nil,
				nil,
			},
			expected: true,
		},
		{
			name: "greater with string and string",
			args: []any{
				"test",
				"test",
			},
			expected: true,
		},
		{
			name: "greater with string and int",
			args: []any{
				"test",
				1,
			},
			expected: false,
		},
		{
			name: "greater with int and int",
			args: []any{
				1,
				1,
			},
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := GreaterOrEquals(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
