package parser

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_EscapeSpecialSequences(t *testing.T) {
	tests := []struct {
		name     string
		inp      string
		expected string
	}{
		{
			name:     "without special sequences",
			inp:      `"hello world\\"`,
			expected: `"hello world\\"`,
		},
		{
			name:     "interpolation",
			inp:      `"Hello, ${var.name}!"`,
			expected: `"Hello, $${var.name}!"`,
		},
		{
			name:     "directive",
			inp:      `"Hello, %{ if true }foo%{ else }bar%{ endif }!"`,
			expected: `"Hello, %%{ if true }foo%%{ else }bar%%{ endif }!"`,
		},
		{
			name:     "interpolation already escaped",
			inp:      `"Hello, $${var.name}!"`,
			expected: `"Hello, $${var.name}!"`,
		},
		{
			name:     "start with special character",
			inp:      `${var.name}!"`,
			expected: `$${var.name}!"`,
		},
		{
			name:     "grok pattern",
			inp:      "# Grok Pattern Template\ngrok_pattern = \"%{TIMESTAMP_ISO8601:time} \\\\[%{NUMBER:pid}\\\\] %{GREEDYDATA:message}\"",
			expected: "# Grok Pattern Template\ngrok_pattern = \"%%{TIMESTAMP_ISO8601:time} \\\\[%%{NUMBER:pid}\\\\] %%{GREEDYDATA:message}\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeSpecialSequences(tt.inp)
			assert.Equal(t, tt.expected, got)

			// We make sure that the characters are properly escaped
			_, diag := hclsyntax.ParseTemplate([]byte(got), "", hcl.InitialPos)
			if diag.HasErrors() {
				require.NoError(t, diag)
			}
		})
	}
}

func Test_ToHcl(t *testing.T) {
	tests := []struct {
		name     string
		block    PlanBlock
		expected string
	}{
		{
			name: "empty block",
			block: PlanBlock{
				BlockType: "resource",
				Type:      "aws_s3_bucket",
				Name:      "empty",
			},
			expected: `resource "aws_s3_bucket" "empty" {
}
`,
		},
		{
			name: "simple attributes",
			block: PlanBlock{
				BlockType: "resource",
				Type:      "aws_instance",
				Name:      "example",
				Attributes: map[string]any{
					"num":     3,
					"boolean": true,
					"str":     "test",
				},
			},
			expected: `resource "aws_instance" "example" {
  boolean = true
  num = 3
  str = "test"
}
`,
		},
		{
			name: "nested blocks",
			block: PlanBlock{
				BlockType: "resource",
				Type:      "aws_security_group",
				Name:      "sg",
				Blocks: []*PlanBlock{
					{
						BlockType: "ingress",
						Attributes: map[string]any{
							"from_port": 80,
							"to_port":   80,
						},
					},
				},
			},
			expected: `resource "aws_security_group" "sg" {
  ingress {
    from_port = 80
    to_port = 80
  }
}
`,
		},
		{
			name: "map key doesn't valid identifier",
			block: PlanBlock{
				BlockType: "resource",
				Type:      "aws_s3_bucket",
				Name:      "name",
				Attributes: map[string]any{
					"tags": map[string]any{
						"foo: /b\"ar": "baz",
					},
				},
			},
			expected: `resource "aws_s3_bucket" "name" {
  tags = {
    "foo: /b\"ar" = "baz"
  }
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sb strings.Builder
			tt.block.toHCL(&sb)
			assert.Equal(t, tt.expected, sb.String())
		})
	}
}
