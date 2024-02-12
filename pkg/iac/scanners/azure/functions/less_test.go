package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Less(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{

		{
			name: "less with nil and string",
			args: []interface{}{
				nil,
				"test",
			},
			expected: false,
		},
		{
			name: "less with nil and nil",
			args: []interface{}{
				nil,
				nil,
			},
			expected: false,
		},
		{
			name: "less with string and string",
			args: []interface{}{
				"test",
				"test",
			},
			expected: false,
		},
		{
			name: "less with string and int",
			args: []interface{}{
				"test",
				1,
			},
			expected: false,
		},
		{
			name: "less with int and int",
			args: []interface{}{
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
		args     []interface{}
		expected interface{}
	}{

		{
			name: "less with nil and string",
			args: []interface{}{
				nil,
				"test",
			},
			expected: false,
		},
		{
			name: "less with nil and nil",
			args: []interface{}{
				nil,
				nil,
			},
			expected: true,
		},
		{
			name: "less with string and string",
			args: []interface{}{
				"test",
				"test",
			},
			expected: true,
		},
		{
			name: "less with string and int",
			args: []interface{}{
				"test",
				1,
			},
			expected: false,
		},
		{
			name: "less with int and int",
			args: []interface{}{
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
