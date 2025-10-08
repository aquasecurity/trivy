package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Length(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected int
	}{
		{
			name: "length of a string",
			args: []any{
				"hello",
			},
			expected: 5,
		},
		{
			name: "length of an empty string",
			args: []any{
				"",
			},
			expected: 0,
		},
		{
			name: "length of an empty slice",
			args: []any{
				[]string{},
			},
			expected: 0,
		},
		{
			name: "length of an slice with items",
			args: []any{
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
