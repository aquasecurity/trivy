package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_If(t *testing.T) {

	tests := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name:     "If with true",
			args:     []any{true, "true", "false"},
			expected: "true",
		},
		{
			name:     "If with false",
			args:     []any{false, "true", "false"},
			expected: "false",
		},
		{
			name: "If with true and slice returned",
			args: []any{
				true,
				[]any{"Hello", "World"},
				[]any{"Goodbye", "World"},
			},
			expected: []any{"Hello", "World"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := If(tt.args...)
			assert.Equal(t, tt.expected, got)
		})
	}

}
