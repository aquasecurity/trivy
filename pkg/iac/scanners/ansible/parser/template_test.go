package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWrapTemplatesQuotes(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "double quotes",
			input:    `foo: {{ bar }}`,
			expected: `foo: "{{ bar }}"`,
		},
		{
			name:     "single quotes",
			input:    `foo: '{{ bar }}'`,
			expected: `foo: '{{ bar }}'`,
		},
		{
			name:     "already double quoted",
			input:    `foo: "{{ bar }}"`,
			expected: `foo: "{{ bar }}"`,
		},
		{
			name:     "mixed spaces",
			input:    `  foo :  {{ bar }}  `,
			expected: `  foo :  "{{ bar }}"  `,
		},
		{
			name:     "non-template",
			input:    `foo: 123`,
			expected: `foo: 123`,
		},
		{
			name:     "multiple_templates",
			input:    "msg: {{ var1 }} and {{ var2 }}",
			expected: `msg: "{{ var1 }} and {{ var2 }}"`,
		},
		{
			name: "multiline",
			input: `s3_bucket:
  name: {{ bucket }}
  public_access: '{{ public_access }}'
`,
			expected: `s3_bucket:
  name: "{{ bucket }}"
  public_access: '{{ public_access }}'
`,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapTemplatesQuotes(tt.input)
			assert.Equal(t, tt.expected, string(got))
		})
	}
}
