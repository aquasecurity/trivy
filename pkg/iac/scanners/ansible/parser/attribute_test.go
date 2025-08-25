package parser

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/orderedmap"
	"github.com/stretchr/testify/assert"
)

func scalar(val any) *Node {
	return &Node{val: &Scalar{Val: val}}
}

func mapping(pairs map[string]*Node) *Mapping {
	m := orderedmap.New[string, *Node](len(pairs))
	for k, v := range pairs {
		m.Set(k, v)
	}
	return &Mapping{Fields: m}
}

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
				val: mapping(map[string]*Node{
					"name": scalar("mys3bucket"),
				}),
			},
			path:     "name",
			expected: "mys3bucket",
		},
		{
			name: "happy",
			attr: Attribute{
				val: mapping(map[string]*Node{
					"tags": {
						val: mapping(map[string]*Node{
							"example": scalar("tag1"),
						}),
					},
				}),
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
