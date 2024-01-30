package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Add(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected int
	}{
		{
			name:     "Add with 1 and 2",
			args:     []interface{}{1, 2},
			expected: 3,
		},
		{
			name:     "Add with 2 and 3",
			args:     []interface{}{2, 3},
			expected: 5,
		},
		{
			name:     "Add with 3 and -4",
			args:     []interface{}{3, -4},
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Add(tt.args...)
			assert.Equal(t, tt.expected, got)
		})
	}
}
