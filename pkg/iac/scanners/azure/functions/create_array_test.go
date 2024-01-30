package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CreateArray(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name: "create array with strings",
			args: []interface{}{
				"Hello",
				"World",
			},
			expected: []interface{}{"Hello", "World"},
		},
		{
			name: "create array with ints",

			args: []interface{}{
				1, 2, 3,
			},
			expected: []interface{}{1, 2, 3},
		},
		{
			name: "create array with arrays",
			args: []interface{}{
				[]interface{}{1, 2, 3},
				[]interface{}{4, 5, 6},
			},
			expected: []interface{}{[]interface{}{1, 2, 3}, []interface{}{4, 5, 6}},
		},
		{
			name: "create arrau with maps",
			args: []interface{}{
				map[string]interface{}{
					"one": "a",
				},
				map[string]interface{}{
					"two": "b",
				},
			},
			expected: []interface{}{
				map[string]interface{}{
					"one": "a",
				},
				map[string]interface{}{
					"two": "b",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := CreateArray(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}

}
