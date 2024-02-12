package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_JSON(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected map[string]interface{}
	}{
		{
			name: "simple json string to json type",
			args: []interface{}{
				`{"hello": "world"}`,
			},
			expected: map[string]interface{}{
				"hello": "world",
			},
		},
		{
			name: "more complex json string to json type",
			args: []interface{}{
				`{"hello": ["world", "world2"]}`,
			},
			expected: map[string]interface{}{
				"hello": []interface{}{"world", "world2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := JSON(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
