package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Join(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{
			name: "join strings with no items",
			args: []any{
				[]string{},
				" ",
			},
			expected: "",
		},
		{
			name: "join strings",
			args: []any{
				[]string{"Hello", "World"},
				" ",
			},
			expected: "Hello World",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Join(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
