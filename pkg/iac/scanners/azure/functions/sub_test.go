package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Sub(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected int
	}{
		{
			name:     "subtract 2 from 5",
			args:     []interface{}{5, 2},
			expected: 3,
		},
		{
			name:     "subtract 2 from 1",
			args:     []interface{}{1, 2},
			expected: -1,
		},
		{
			name:     "subtract 3 from 2",
			args:     []interface{}{2, 3},
			expected: -1,
		},
		{
			name:     "subtract -4 from 3",
			args:     []interface{}{3, -4},
			expected: 7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sub(tt.args...)
			assert.Equal(t, tt.expected, got)
		})
	}
}
