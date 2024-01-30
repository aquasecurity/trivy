package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Intersect(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name: "intersect two arrays",
			args: []interface{}{
				[]interface{}{"a", "b", "c"},
				[]interface{}{"b", "c", "d"},
			},
			expected: []interface{}{"b", "c"},
		},
		{
			name: "intersect three arrays",
			args: []interface{}{
				[]interface{}{"a", "b", "c", "d"},
				[]interface{}{"b", "c", "d"},
				[]interface{}{"b", "c"},
			},
			expected: []interface{}{"b", "c"},
		},
		{
			name: "intersect two arrays with one empty",
			args: []interface{}{
				[]interface{}{"a", "b", "c"},
				[]interface{}{},
			},
			expected: []interface{}(nil),
		},
		{
			name: "intersect two arrays with both empty",
			args: []interface{}{
				[]interface{}{},
				[]interface{}{},
			},
			expected: []interface{}(nil),
		},
		{
			name: "intersect two arrays with both nil",
			args: []interface{}{
				nil,
				nil,
			},
			expected: []interface{}{},
		},
		{
			name: "intersect two maps",
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
				"b": "b",
				"c": "c",
			},
		},
		{
			name: "intersect three maps",
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
					"d": "d",
				},
			},
			expected: map[string]interface{}{
				"b": "b",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Intersection(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
