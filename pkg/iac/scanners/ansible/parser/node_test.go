package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNode_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected Node
	}{
		{
			name: "happy",
			src: `name: testname
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
`,
			expected: Node{
				rng: Range{0, 11},
				val: map[string]*Node{
					"name": {
						rng: Range{1, 1},
						val: "testname",
					},
					"len": {
						rng: Range{2, 2},
						val: 100,
					},
					"keys": {
						rng: Range{3, 7},
						val: []*Node{
							{
								rng: Range{4, 4},
								val: "a",
							},
							{
								rng: Range{5, 5},
								val: 101,
							},
							{
								rng: Range{6, 6},
								val: true,
							},
							{
								rng: Range{7, 7},
								val: nil,
							},
						},
					},
					"state": {
						rng: Range{8, 11},
						val: map[string]*Node{
							"name": {
								rng: Range{9, 9},
								val: "test",
							},
							"len": {
								rng: Range{10, 10},
								val: 200,
							},
							"foo": {
								rng: Range{11, 11},
								val: nil,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var node Node
			err := yaml.Unmarshal([]byte(tt.src), &node)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, node)
		})
	}
}
