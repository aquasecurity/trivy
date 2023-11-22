package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Or(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected bool
	}{
		{
			name:     "And with same 2 bools",
			args:     []interface{}{true, true},
			expected: true,
		},
		{
			name:     "And with same 3 bools",
			args:     []interface{}{true, true, true},
			expected: true,
		},
		{
			name:     "And with different 4 bools",
			args:     []interface{}{true, true, false, true},
			expected: true,
		},
		{
			name:     "And with same false 4 bools",
			args:     []interface{}{false, false, false, false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Or(tt.args...)
			assert.Equal(t, tt.expected, got)
		})
	}
}
