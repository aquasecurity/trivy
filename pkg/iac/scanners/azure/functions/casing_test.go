package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ToLower(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{
			name: "lowercase a string",
			args: []any{
				"HELLO",
			},
			expected: "hello",
		},
		{
			name: "lowercase a string with a non-string input",
			args: []any{
				10,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := ToLower(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}

func Test_ToUpper(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{
			name: "uppercase a string",
			args: []any{
				"hello",
			},
			expected: "HELLO",
		},
		{
			name: "uppercase a string with a non-string input",
			args: []any{
				10,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := ToUpper(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}
