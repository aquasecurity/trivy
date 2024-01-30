package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Union(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name: "union single array",
			args: []interface{}{
				[]interface{}{"a", "b", "c"},
			},
			expected: []interface{}{"a", "b", "c"},
		},
		{
			name: "union two arrays",
			args: []interface{}{
				[]interface{}{"a", "b", "c"},
				[]interface{}{"b", "c", "d"},
			},
			expected: []interface{}{"a", "b", "c", "d"},
		},
		{
			name: "union two arrays",
			args: []interface{}{
				[]interface{}{"a", "b", "c"},
				[]interface{}{"b", "c", "d"},
				[]interface{}{"b", "c", "d", "e"},
			},
			expected: []interface{}{"a", "b", "c", "d", "e"},
		},
		{
			name: "union single maps",
			args: []interface{}{
				map[string]interface{}{
					"a": "a",
					"b": "b",
					"c": "c",
				},
			},
			expected: map[string]interface{}{
				"a": "a",
				"b": "b",
				"c": "c",
			},
		},
		{
			name: "union two maps",
			args: []interface{}{
				map[string]interface{}{
					"a": "a",
					"b": "b",
					"c": "c",
				},
				map[string]interface{}{
					"b": "b",
					"c": "c",
					"d": "d",
				},
			},
			expected: map[string]interface{}{
				"a": "a",
				"b": "b",
				"c": "c",
				"d": "d",
			},
		},
		{
			name: "union three maps",
			args: []interface{}{
				map[string]interface{}{
					"a": "a",
					"b": "b",
					"c": "c",
				},
				map[string]interface{}{
					"b": "b",
					"c": "c",
					"d": "d",
				},
				map[string]interface{}{
					"b": "b",
					"c": "c",
					"e": "e",
				},
			},
			expected: map[string]interface{}{
				"a": "a",
				"b": "b",
				"c": "c",
				"d": "d",
				"e": "e",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Union(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
