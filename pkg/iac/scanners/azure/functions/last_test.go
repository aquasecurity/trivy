package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Last(t *testing.T) {
	test := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name: "last in empty string",
			args: []interface{}{
				"",
			},
			expected: "",
		},
		{
			name: "last in string",
			args: []interface{}{
				"Hello",
			},
			expected: "o",
		},
		{
			name: "last in empty slice",
			args: []interface{}{
				[]string{},
			},
			expected: "",
		},
		{
			name: "last in slice",
			args: []interface{}{
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
