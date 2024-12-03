package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Uri(t *testing.T) {
	tests := []struct {
		name     string
		args     []any
		expected string
	}{
		{
			name: "uri from a base and relative with no trailing slash",
			args: []any{
				"http://contoso.org/firstpath",
				"myscript.sh",
			},
			expected: "http://contoso.org/firstpath/myscript.sh",
		},
		{
			name: "uri from a base and relative with  trailing slash",
			args: []any{
				"http://contoso.org/firstpath/",
				"myscript.sh",
			},
			expected: "http://contoso.org/firstpath/myscript.sh",
		},
		{
			name: "uri from a base with trailing slash and relative with ../",
			args: []any{
				"http://contoso.org/firstpath/",
				"../myscript.sh",
			},
			expected: "http://contoso.org/myscript.sh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Uri(tt.args...)
			require.Equal(t, tt.expected, actual)
		})
	}

}
