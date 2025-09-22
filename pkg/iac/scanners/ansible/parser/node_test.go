package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/orderedmap"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

func mustNodeFromYAML(t *testing.T, src string) *Node {
	t.Helper()
	var n Node
	require.NoError(t, decodeYAML([]byte(src), &n))
	return &n
}

func TestNode_UnmarshalYAML(t *testing.T) {
	src := `name: {{ testname }}
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
	expected := &Node{
		rng: Range{0, 11},
		val: &Mapping{
			Fields: func() *orderedmap.OrderedMap[string, *Node] {
				m := orderedmap.New[string, *Node](4)
				m.Set("name", &Node{rng: Range{1, 1}, val: &Scalar{Val: "{{ testname }}"}})
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

	n := mustNodeFromYAML(t, src)
	assert.Equal(t, expected, n)
}

func TestNode_NodeAt(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		path     string
		expected any
	}{
		{
			name:     "first level",
			src:      `name: mys3bucket`,
			path:     "name",
			expected: "mys3bucket",
		},
		{
			name: "happy",
			src: `tags:
  example: tag1`,
			path:     "tags.example",
			expected: "tag1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := mustNodeFromYAML(t, tt.src)
			got := n.NodeAt(tt.path).Value()
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestNode_Render(t *testing.T) {
	tests := []struct {
		name    string
		yamlSrc string
		vars    map[string]any
		want    string
		wantErr bool
	}{
		{
			name:    "simple interpolation",
			yamlSrc: `"{{ b }} {{ c }}"`,
			vars: map[string]any{
				"b": "hello",
				"c": "world",
			},
			want:    "hello world\n",
			wantErr: false,
		},
		{
			name:    "chained references",
			yamlSrc: `"{{ b }}"`,
			vars: map[string]any{
				"b": "{{ c }}",
				"c": "final",
			},
			want:    "final\n",
			wantErr: false,
		},
		{
			name:    "cyclic reference",
			yamlSrc: `"{{ a }}"`,
			vars: map[string]any{
				"a": "{{ a }}",
			},
			wantErr: true,
		},
		{
			name:    "shared variable",
			yamlSrc: `"{{ x }} and {{ y }}"`,
			vars: map[string]any{
				"x":      "{{ shared }}",
				"y":      "{{ shared }}",
				"shared": "value",
			},
			want:    "value and value\n",
			wantErr: false,
		},
		{
			name:    "undefined variable",
			yamlSrc: `"{{ missing }}"`,
			vars:    make(map[string]any),
			wantErr: true,
		},
		{
			name:    "empty template",
			yamlSrc: `""`,
			vars:    make(map[string]any),
			want: `""
`,
			wantErr: false,
		},
		{
			name:    "mixed literal and template",
			yamlSrc: `"start {{ a }} end"`,
			vars: map[string]any{
				"a": "{{ b }}",
				"b": "middle",
			},
			want:    "start middle end\n",
			wantErr: false,
		},
		{
			name: "sequence and mapping",
			yamlSrc: `
list:
  - "{{ x }}"
  - "{{ y }}"
dict:
  key1: "{{ a }}"
  key2: "{{ b }}"
`,
			vars: map[string]any{"x": "1", "y": "2", "a": "A", "b": "B"},
			want: `list:
    - "1"
    - "2"
dict:
    key1: A
    key2: B
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := mustNodeFromYAML(t, tt.yamlSrc)
			got, err := n.Render(vars.NewVars(tt.vars, 0))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			marshaled, err := yaml.Marshal(got)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(marshaled))
		})
	}
}

func TestNode_Subtree(t *testing.T) {
	src := `name: test
len: 100
state:
    foo: bar
    num: 42
elems:
    - foo: 1
      baz: 2
    - bar
`
	tests := []struct {
		name     string
		query    Range
		expected string
	}{
		{
			name:     "no cover",
			query:    Range{0, 0},
			expected: "null\n",
		},
		{
			name:     "single top-level field",
			query:    Range{1, 1},
			expected: "name: test\n",
		},
		{
			name:     "single nested field",
			query:    Range{5, 5},
			expected: "num: 42\n",
		},
		{
			name:  "nested mapping",
			query: Range{4, 5},
			expected: `foo: bar
num: 42
`,
		},
		{
			name:  "map with some fields",
			query: Range{6, 7},
			expected: `elems:
    - foo: 1
`,
		},
		{
			name:  "single nested element",
			query: Range{9, 9},
			expected: `- bar
`,
		},
		{
			name:  "nested slice",
			query: Range{7, 9},
			expected: `- foo: 1
  baz: 2
- bar
`,
		},
		{
			name:  "nested slice elem",
			query: Range{9, 9},
			expected: `- bar
`,
		},
		{
			name:     "full range",
			query:    Range{1, 9},
			expected: src,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := mustNodeFromYAML(t, src)
			subtree := node.Subtree(tt.query)
			marshaled, err := yaml.Marshal(subtree)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(marshaled))
		})
	}
}
