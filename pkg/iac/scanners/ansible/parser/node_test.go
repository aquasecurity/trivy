package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/orderedmap"
)

func TestNode_UnmarshalYAML(t *testing.T) {
	src := `name: testname
len: 100
keys:
  - a
  - 101
  - true
  - null
state:
  name: test
  len: 200 
  foo: null
`
	expected := Node{
		rng: Range{0, 11},
		val: &Mapping{
			Fields: func() *orderedmap.OrderedMap[string, *Node] {
				m := orderedmap.New[string, *Node](4)
				m.Set("name", &Node{rng: Range{1, 1}, val: &Scalar{Val: "testname"}})
				m.Set("len", &Node{rng: Range{2, 2}, val: &Scalar{Val: 100}})
				m.Set("keys", &Node{
					rng: Range{3, 7},
					val: &Sequence{
						Items: []*Node{
							{rng: Range{4, 4}, val: &Scalar{Val: "a"}},
							{rng: Range{5, 5}, val: &Scalar{Val: 101}},
							{rng: Range{6, 6}, val: &Scalar{Val: true}},
							{rng: Range{7, 7}, val: nil},
						},
					},
				})
				m.Set("state", &Node{
					rng: Range{8, 11},
					val: &Mapping{
						Fields: func() *orderedmap.OrderedMap[string, *Node] {
							sm := orderedmap.New[string, *Node](3)
							sm.Set("name", &Node{rng: Range{9, 9}, val: &Scalar{Val: "test"}})
							sm.Set("len", &Node{rng: Range{10, 10}, val: &Scalar{Val: 200}})
							sm.Set("foo", &Node{rng: Range{11, 11}, val: nil})
							return sm
						}(),
					},
				})
				return m
			}(),
		},
	}

	var node Node
	err := yaml.Unmarshal([]byte(src), &node)
	require.NoError(t, err)

	assert.Equal(t, expected, node)
}
