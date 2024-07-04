package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Last(t *testing.T) {
	test := []struct {
		name     string
		args     []any
		expected any
	}{
		{
			name: "last in empty string",
			args: []any{
				"",
			},
			expected: "",
		},
		{
			name: "last in string",
			args: []any{
				"Hello",
			},
			expected: "o",
		},
		{
			name: "last in empty slice",
			args: []any{
				[]string{},
			},
			expected: "",
		},
		{
			name: "last in slice",
			args: []any{
				[]string{"Hello", "World"},
			},
			expected: "World",
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			actual := Last(tt.args...)
			require.Equal(t, tt.expected, actual)
		})
	}
}
