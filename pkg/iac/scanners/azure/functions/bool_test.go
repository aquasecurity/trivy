package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Bool(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected bool
	}{
		{
			name:     "Bool with true",
			args:     []interface{}{true},
			expected: true,
		},
		{
			name:     "Bool with false",
			args:     []interface{}{false},
			expected: false,
		},
		{
			name:     "Bool with 1",
			args:     []interface{}{1},
			expected: true,
		},
		{
			name:     "Bool with 0",
			args:     []interface{}{0},
			expected: false,
		},
		{
			name:     "Bool with true string",
			args:     []interface{}{"true"},
			expected: true,
		},
		{
			name:     "Bool with false string",
			args:     []interface{}{"false"},
			expected: false,
		},
		{
			name:     "Bool with 1 string",
			args:     []interface{}{"1"},
			expected: true,
		},
		{
			name:     "Bool with 0 string",
			args:     []interface{}{"0"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Bool(tt.args...)
			assert.Equal(t, tt.expected, got)
		})
	}
}
