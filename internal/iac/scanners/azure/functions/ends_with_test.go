package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_EndsWith(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected bool
	}{
		{
			name: "string ends with",
			args: []any{
				"Hello world!",
				"world!",
			},
			expected: true,
		},
		{
			name: "string does not end with",
			args: []any{
				"Hello world!",
				"world",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := EndsWith(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}
