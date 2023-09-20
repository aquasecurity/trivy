package slices

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMerge(t *testing.T) {
	tests := []struct {
		name string
		args [][]int
		want []int
	}{
		{
			"nil",
			[][]int{nil},
			[]int{},
		},
		{
			"empty",
			[][]int{},
			[]int{},
		},
		{
			"empties",
			[][]int{{}, {}},
			[]int{},
		},
		{
			"same length",
			[][]int{{1, 3, 5}, {2, 4, 6}},
			[]int{1, 3, 5, 2, 4, 6},
		},
		{
			"different length",
			[][]int{{1, 3, 5, 6}, {2, 4}},
			[]int{1, 3, 5, 6, 2, 4},
		},
		{
			"many slices",
			[][]int{{1}, {2, 5, 8}, {3, 6}, {4, 7, 9, 10}},
			[]int{1, 2, 5, 8, 3, 6, 4, 7, 9, 10},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Merge(tt.args...))
		})
	}
}
