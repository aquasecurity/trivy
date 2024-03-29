package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_First(t *testing.T) {
	test := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name: "first in empty string",
			args: []interface{}{
				"",
			},
			expected: "",
		},
		{
			name: "first in string",
			args: []interface{}{
				"Hello",
			},
			expected: "H",
		},
		{
			name: "first in empty slice",
			args: []interface{}{
				[]string{},
			},
			expected: "",
		},
		{
			name: "first in slice",
			args: []interface{}{
				[]string{"Hello", "World"},
			},
			expected: "Hello",
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			actual := First(tt.args...)
			require.Equal(t, tt.expected, actual)
		})
	}
}
