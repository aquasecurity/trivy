package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestUnwrapTemplates(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected string
	}{
		{
			name: "single template",
			src: `
{{ name }}
`,
			expected: `'{{ name }}'
`,
		},
		{
			name: "nested template in mapping",
			src: `test:
  {{ nested }}
`,
			expected: `test: '{{ nested }}'
`,
		},
		{
			name: "sequence with templates",
			src: `- {{ first }}
- value
- {{ second }}
`,
			expected: `- '{{ first }}'
- value
- '{{ second }}'
`,
		},
		{
			name: "non-template values remain",
			src: `plain: value
seq:
    - 123
    - text
`,
			expected: `plain: value
seq:
    - 123
    - text
`,
		},
		{
			name: "mapping remains unchanged",
			src: `simple_map: { key1: val1, key2: val2 }
nested_map:
    inner: { a: 1, b: 2 }
`,
			expected: `simple_map: {key1: val1, key2: val2}
nested_map:
    inner: {a: 1, b: 2}
`,
		},
		{
			name: "template inside inline mapping",
			src:  `inline_map: { value: {{ name }}, static: fixed }`,
			expected: `inline_map: {value: '{{ name }}', static: fixed}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var root yaml.Node
			err := yaml.Unmarshal([]byte(tt.src), &root)
			require.NoError(t, err)

			unwrapTemplates(&root)

			out, err := yaml.Marshal(&root)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, string(out))
		})
	}
}
