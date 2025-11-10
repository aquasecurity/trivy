package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Mul(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected int
	}{
		{
			name:     "multiply -2 by 1",
			args:     []any{-2, 1},
			expected: -2,
		},
		{
			name:     "multiply 4 by 2",
			args:     []any{4, 2},
			expected: 8,
		},
		{
			name:     "multiply 6 by 3",
			args:     []any{6, 3},
			expected: 18,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Mul(tt.args...)
			assert.Equal(t, tt.expected, got)
		})
	}
}
