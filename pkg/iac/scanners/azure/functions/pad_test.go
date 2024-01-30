package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_PadLeft(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "pad left with a input smaller than length",
			args: []interface{}{
				"1234",
				8,
				"0",
			},
			expected: "00001234",
		},
		{
			name: "pad left with a input larger than length",
			args: []interface{}{
				"1234",
				2,
				"0",
			},
			expected: "1234",
		},
		{
			name: "pad left with a input same as than length",
			args: []interface{}{
				"1234",
				4,
				"0",
			},
			expected: "1234",
		},
		{
			name: "pad left with larger padding character",
			args: []interface{}{
				"1234",
				8,
				"00",
			},
			expected: "00001234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := PadLeft(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}
