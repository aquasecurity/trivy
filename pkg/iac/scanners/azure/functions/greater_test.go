package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Greater(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{

		{
			name: "greater with nil and string",
			args: []interface{}{
				nil,
				"test",
			},
			expected: false,
		},
		{
			name: "greater with nil and nil",
			args: []interface{}{
				nil,
				nil,
			},
			expected: false,
		},
		{
			name: "greater with string and string",
			args: []interface{}{
				"test",
				"test",
			},
			expected: false,
		},
		{
			name: "greater with string and int",
			args: []interface{}{
				"test",
				1,
			},
			expected: false,
		},
		{
			name: "greater with int and int",
			args: []interface{}{
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
		args     []interface{}
		expected interface{}
	}{

		{
			name: "greater with nil and string",
			args: []interface{}{
				nil,
				"test",
			},
			expected: false,
		},
		{
			name: "greater with nil and nil",
			args: []interface{}{
				nil,
				nil,
			},
			expected: true,
		},
		{
			name: "greater with string and string",
			args: []interface{}{
				"test",
				"test",
			},
			expected: true,
		},
		{
			name: "greater with string and int",
			args: []interface{}{
				"test",
				1,
			},
			expected: false,
		},
		{
			name: "greater with int and int",
			args: []interface{}{
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
