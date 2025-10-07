package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Max(t *testing.T) {
	test := []struct {
		name     string
		args     []any
		expected int
	}{
		{
			name: "max of empty slice",
			args: []any{
				[]int{},
			},
			expected: 0,
		},
		{
			name: "max of slice",
			args: []any{
				[]int{1, 2, 3},
			},
			expected: 3,
		},
		{
			name: "max of slice with negative numbers",
			args: []any{
				[]int{-1, -2, -3},
			},
			expected: -1,
		},
		{
			name: "max of slice with negative and positive numbers",
			args: []any{
				[]int{-1, 2, -3},
			},
			expected: 2,
		},
		{
			name: "max of comma separated numbers",
			args: []any{
				1, 2, 3, 4, 5,
			},
			expected: 5,
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			actual := Max(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
