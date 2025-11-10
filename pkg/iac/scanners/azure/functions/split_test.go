package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Split(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected []string
	}{
		{
			name: "split a string",
			args: []any{
				"hello, world",
				",",
			},
			expected: []string{"hello", " world"},
		},
		{
			name: "split a string with multiple separators",
			args: []any{
				"one;two,three",
				[]string{",", ";"},
			},
			expected: []string{"one", "two", "three"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Split(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
