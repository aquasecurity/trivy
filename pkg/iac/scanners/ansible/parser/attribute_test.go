package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttribute_GetNestedAttr(t *testing.T) {
	tests := []struct {
		name     string
		attr     Attribute
		path     string
		expected any
	}{
		{
			name: "first level",
			attr: Attribute{
				val: map[string]*Node{
					"name": {
						val: "mys3bucket",
					},
				},
			},
			path:     "name",
			expected: "mys3bucket",
		},
		{
			name: "happy",
			attr: Attribute{
				val: map[string]*Node{
					"tags": {
						val: map[string]*Node{
							"example": {
								val: "tag1",
							},
						},
					},
				},
			},
			path:     "tags.example",
			expected: "tag1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.attr.GetNestedAttr(tt.path).Value()
			assert.Equal(t, tt.expected, got)
		})
	}
}
