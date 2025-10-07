package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Bool(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected bool
	}{
		{
			name:     "Bool with true",
			args:     []any{true},
			expected: true,
		},
		{
			name:     "Bool with false",
			args:     []any{false},
			expected: false,
		},
		{
			name:     "Bool with 1",
			args:     []any{1},
			expected: true,
		},
		{
			name:     "Bool with 0",
			args:     []any{0},
			expected: false,
		},
		{
			name:     "Bool with true string",
			args:     []any{"true"},
			expected: true,
		},
		{
			name:     "Bool with false string",
			args:     []any{"false"},
			expected: false,
		},
		{
			name:     "Bool with 1 string",
			args:     []any{"1"},
			expected: true,
		},
		{
			name:     "Bool with 0 string",
			args:     []any{"0"},
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
