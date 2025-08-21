package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

func TestEvaluateTemplate(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		vars      vars.Vars
		expected  string
		expectErr bool
	}{
		{
			name:     "simple variable",
			input:    "Hello {{ name }}",
			vars:     vars.Vars{"name": "World"},
			expected: "Hello World",
		},
		{
			name:     "arithmetic",
			input:    "{{ a + b }}",
			vars:     vars.Vars{"a": 2, "b": 3},
			expected: "5",
		},
		{
			name:     "if else true",
			input:    "{% if flag %}Yes{% else %}No{% endif %}",
			vars:     vars.Vars{"flag": true},
			expected: "Yes",
		},
		{
			name:     "if else false",
			input:    "{% if flag %}Yes{% else %}No{% endif %}",
			vars:     vars.Vars{"flag": false},
			expected: "No",
		},
		{
			name:      "invalid template",
			input:     "{{ foo ",
			vars:      vars.Vars{},
			expectErr: true,
		},
		{
			name:      "missing variable",
			input:     "Hello {{ name }}",
			vars:      vars.Vars{},
			expectErr: true,
		},
		{
			name:     "multiple variables",
			input:    "{{ greeting }}, {{ name }}!",
			vars:     vars.Vars{"greeting": "Hi", "name": "Alice"},
			expected: "Hi, Alice!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateTemplate(tt.input, tt.vars)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

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
			assert.Equal(t, tt.expected, got)
		})
	}
}
