package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Empty(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected bool
	}{
		{
			name: "string is empty",
			args: []interface{}{
				"",
			},
			expected: true,
		},
		{
			name: "string is not empty",
			args: []interface{}{
				"hello, world",
			},
			expected: false,
		},
		{
			name: "array is empty",
			args: []interface{}{
				[]string{},
			},
			expected: true,
		},
		{
			name: "array is not empty",
			args: []interface{}{
				[]string{"Hello", "World"},
			},
			expected: false,
		},
		{
			name: "map is empty",
			args: []interface{}{
				map[string]interface{}{},
			},
			expected: true,
		},
		{
			name: "map is not empty",
			args: []interface{}{
				map[string]interface{}{
					"hello": "world",
				},
				"world",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doesContain := Empty(tt.args...)
			require.Equal(t, tt.expected, doesContain)
		})
	}
}
