package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CreateObject(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name:     "CreateObject with no args",
			args:     []interface{}{},
			expected: map[string]interface{}{},
		},
		{
			name:     "CreateObject with one arg",
			args:     []interface{}{"foo", "bar"},
			expected: map[string]interface{}{"foo": "bar"},
		},
		{
			name:     "CreateObject with two args",
			args:     []interface{}{"foo", "bar", "baz", "qux"},
			expected: map[string]interface{}{"foo": "bar", "baz": "qux"},
		},
		{
			name:     "CreateObject with three args",
			args:     []interface{}{"foo", "bar", "baz", 1, "quux", true},
			expected: map[string]interface{}{"foo": "bar", "baz": 1, "quux": true},
		},
		{
			name:     "CreateObject with odd number of args",
			args:     []interface{}{"foo", "bar", "baz"},
			expected: map[string]interface{}{},
		},
		{
			name: "CreateObject with odd number of args",
			args: []interface{}{"foo", "bar", "baz", []string{"Hello", "World"}},
			expected: map[string]interface{}{
				"foo": "bar",
				"baz": []string{
					"Hello", "World",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CreateObject(tt.args...)
			assert.Equal(t, tt.expected, got)
		})
	}

}
