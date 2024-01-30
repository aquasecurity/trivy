package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Div(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected int
	}{
		{
			name:     "Div 2 by 1",
			args:     []interface{}{2, 1},
			expected: 2,
		},
		{
			name:     "Div 4 by 2",
			args:     []interface{}{4, 2},
			expected: 2,
		},
		{
			name:     "Div 6 by 2",
			args:     []interface{}{6, 2},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Div(tt.args...)
			assert.Equal(t, tt.expected, got)
		})
	}
}
