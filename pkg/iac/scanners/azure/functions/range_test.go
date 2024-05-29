package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Range(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name: "range for 3 from 1",
			args: []any{
				1,
				3,
			},
			expected: []int{1, 2, 3},
		},
		{
			name: "range with for 10 from 3",
			args: []any{
				3,
				10,
			},
			expected: []int{3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		},
		{
			name: "range with for 10 from -10",
			args: []any{
				-10,
				10,
			},
			expected: []int{-10, -9, -8, -7, -6, -5, -4, -3, -2, -1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Range(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}
