package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SubString(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{
			name: "substring a string",
			args: []any{
				"hello",
				1,
				3,
			},
			expected: "ell",
		},
		{
			name: "substring a string with no upper bound",
			args: []any{
				"hello",
				1,
			},
			expected: "ello",
		},
		{
			name: "substring a string with start higher than the length",
			args: []any{
				"hello",
				10,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := SubString(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
