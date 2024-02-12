package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_StartsWith(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected bool
	}{
		{
			name: "string ends with",
			args: []interface{}{
				"Hello, world!",
				"Hello,",
			},
			expected: true,
		},
		{
			name: "string does not end with",
			args: []interface{}{
				"Hello world!",
				"Hello,",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := StartsWith(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}
