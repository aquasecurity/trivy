package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_First(t *testing.T) {
	test := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name: "first in empty string",
			args: []any{
				"",
			},
			expected: "",
		},
		{
			name: "first in string",
			args: []any{
				"Hello",
			},
			expected: "H",
		},
		{
			name: "first in empty slice",
			args: []any{
				[]string{},
			},
			expected: "",
		},
		{
			name: "first in slice",
			args: []any{
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
