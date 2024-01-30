package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Equals(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name: "equals with nil",
			args: []interface{}{
				nil,
			},
			expected: false,
		},
		{
			name: "equals with nil and string",
			args: []interface{}{
				nil,
				"test",
			},
			expected: false,
		},
		{
			name: "equals with nil and string and int",
			args: []interface{}{
				nil,
				"test",
				1,
			},
			expected: false,
		},
		{
			name: "equals with nil and nil and array",
			args: []interface{}{
				nil,
				nil,
				[]interface{}{"a", "b", "c"},
			},
			expected: false,
		},
		{
			name: "equals with nil and nil",
			args: []interface{}{
				nil,
				nil,
			},
			expected: true,
		},
		{
			name: "equals with string and string",
			args: []interface{}{
				"test",
				"test",
			},
			expected: true,
		},
		{
			name: "equals with string and string",
			args: []interface{}{
				"test",
				"test1",
			},
			expected: false,
		},
		{
			name: "equals with int and int",
			args: []interface{}{
				1,
				1,
			},
			expected: true,
		},
		{
			name: "equals with int and int",
			args: []interface{}{
				1,
				2,
			},
			expected: false,
		},
		{
			name: "equals with array and array",
			args: []interface{}{
				[]interface{}{"a", "b", "c"},
				[]interface{}{"a", "b", "c"},
			},
			expected: true,
		},
		{
			name: "equals with array and array",
			args: []interface{}{
				[]interface{}{"a", "b", "c"},
				[]interface{}{"a", "b", "d"},
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
