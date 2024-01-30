package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Length(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected int
	}{
		{
			name: "length of a string",
			args: []interface{}{
				"hello",
			},
			expected: 5,
		},
		{
			name: "length of an empty string",
			args: []interface{}{
				"",
			},
			expected: 0,
		},
		{
			name: "length of an empty slice",
			args: []interface{}{
				[]string{},
			},
			expected: 0,
		},
		{
			name: "length of an slice with items",
			args: []interface{}{
				[]string{
					"hello", "world",
				},
			},
			expected: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Length(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
