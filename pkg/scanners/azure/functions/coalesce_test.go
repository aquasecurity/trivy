package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Coalesce(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name: "coalesce with nil",
			args: []interface{}{
				nil,
			},
			expected: nil,
		},
		{
			name: "coalesce with nil and string",
			args: []interface{}{
				nil,
				"test",
			},
			expected: "test",
		},
		{
			name: "coalesce with nil and string and int",
			args: []interface{}{
				nil,
				"test",
				1,
			},
			expected: "test",
		},
		{
			name: "coalesce with nil and nil and array",
			args: []interface{}{
				nil,
				nil,
				[]interface{}{"a", "b", "c"},
			},
			expected: []interface{}{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Coalesce(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
