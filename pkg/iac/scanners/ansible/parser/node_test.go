package parser

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
state:
  name: test
  len: 200 
`,
			expected: Node{
				rng: Range{0, 9},
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
						rng: Range{3, 6},
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
						},
					},
					"state": {
						rng: Range{7, 9},
						val: map[string]*Node{
							"name": {
								rng: Range{8, 8},
								val: "test",
							},
							"len": {
								rng: Range{9, 9},
								val: 200,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attr Node
			err := yaml.Unmarshal([]byte(tt.src), &attr)
			require.NoError(t, err)

			diff := cmp.Diff(tt.expected, attr, cmp.AllowUnexported(Node{}, Range{}), cmpopts.IgnoreFields(Node{}, "metadata"))

			if diff != "" {
				t.Error(diff)
			}
		})
	}
}
