package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Not(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected bool
	}{
		{
			name:     "Not with true",
			args:     []any{true},
			expected: false,
		},
		{
			name:     "Not with false",
			args:     []any{false},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Not(tt.args...)
			assert.Equal(t, tt.expected, got)
		})
	}
}
