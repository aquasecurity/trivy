package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Min(t *testing.T) {
	test := []struct {
		name     string
		args     []any
		expected int
	}{
		{
			name: "min of empty slice",
			args: []any{
				[]int{},
			},
			expected: 0,
		},
		{
			name: "min of slice",
			args: []any{
				[]int{1, 2, 3},
			},
			expected: 1,
		},
		{
			name: "min of slice with negative numbers",
			args: []any{
				[]int{-1, -2, -3},
			},
			expected: -3,
		},
		{
			name: "min of slice with negative and positive numbers",
			args: []any{
				[]int{-1, 2, -3},
			},
			expected: -3,
		},
		{
			name: "min of comma separated numbers",
			args: []any{
				1, 2, 3, 4, 5,
			},
			expected: 1,
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			actual := Min(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
