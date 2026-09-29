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
		vars      vars.PlainVars
		expected  string
		expectErr bool
	}{
		{
			name:     "simple variable",
			input:    "Hello {{ name }}",
			vars:     vars.PlainVars{"name": "World"},
			expected: "Hello World",
		},
		{
			name:     "arithmetic",
			input:    "{{ a + b }}",
			vars:     vars.PlainVars{"a": 2, "b": 3},
			expected: "5",
		},
		{
			name:     "if else true",
			input:    "{% if flag %}Yes{% else %}No{% endif %}",
			vars:     vars.PlainVars{"flag": true},
			expected: "Yes",
		},
		{
			name:     "if else false",
			input:    "{% if flag %}Yes{% else %}No{% endif %}",
			vars:     vars.PlainVars{"flag": false},
			expected: "No",
		},
		{
			name:      "invalid template",
			input:     "{{ foo ",
			vars:      vars.PlainVars{},
			expectErr: true,
		},
		{
			name:      "missing variable",
			input:     "Hello {{ name }}",
			vars:      vars.PlainVars{},
			expectErr: true,
		},
		{
			name:     "multiple variables",
			input:    "{{ greeting }}, {{ name }}!",
			vars:     vars.PlainVars{"greeting": "Hi", "name": "Alice"},
			expected: "Hi, Alice!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variables := vars.NewVars(tt.vars, 0)
			got, err := evaluateTemplate(tt.input, variables)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}
