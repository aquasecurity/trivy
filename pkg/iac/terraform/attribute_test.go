package terraform

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/json"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_AllReferences(t *testing.T) {
	cases := []struct {
		input string
		refs  []string
	}{
		{
			input: "42", // literal
			refs:  []string{},
		},
		{
			input: "5 == 5", // comparison
			refs:  []string{},
		},
		{
			input: "var.foo",
			refs:  []string{"variable.foo"},
		},
		{
			input: "resource.foo.bar[local.idx].name",
			refs:  []string{"foo.bar", "locals.idx"},
		},
		{
			input: "resource.foo.bar[0].name",
			refs:  []string{"foo.bar[0].name"},
		},
		{
			input: "resource.aws_instance.id",
			refs:  []string{"aws_instance.id"},
		},
		{
			input: "data.aws_ami.ubuntu.most_recent",
			refs:  []string{"data.aws_ami.ubuntu.most_recent"},
		},
		{
			input: "5 == 5 ? var.foo : data.aws_ami.ubuntu.most_recent", // conditional
			refs:  []string{"variable.foo", "data.aws_ami.ubuntu.most_recent"},
		},
		{
			input: `{x = 1, y = data.aws_ami.ubuntu.most_recent}`,
			refs:  []string{"data.aws_ami.ubuntu.most_recent"},
		},
		{
			input: `{foo = 1 == 1 ? var.bar : data.aws_ami.ubuntu.most_recent}`,
			refs:  []string{"variable.bar", "data.aws_ami.ubuntu.most_recent"},
		},
		{
			input: `[var.foo, var.bar]`,
			refs:  []string{"variable.foo", "variable.bar"},
		},
		{
			// Expression in the key
			input: `{(local.foo): local.bar}`,
			refs:  []string{"locals.foo", "locals.bar"},
		},
	}

	for _, test := range cases {
		t.Run(test.input, func(t *testing.T) {
			ctx := context.NewContext(&hcl.EvalContext{}, nil)

			exp, diag := hclsyntax.ParseExpression([]byte(test.input), "", hcl.Pos{Line: 1, Column: 1})
			if diag.HasErrors() {
				require.NoError(t, diag)
			}

			a := NewAttribute(&hcl.Attribute{
				Name:      "test",
				Expr:      exp,
				Range:     hcl.Range{},
				NameRange: hcl.Range{},
			}, ctx, "", types.Metadata{}, Reference{}, "", nil)

			refs := a.AllReferences()
			humanRefs := make([]string, 0, len(refs))
			for _, ref := range refs {
				humanRefs = append(humanRefs, ref.HumanReadable())
			}

			require.ElementsMatch(t, test.refs, humanRefs)
		})
	}
}

func Test_AllReferences_JSON(t *testing.T) {
	tests := []struct {
		src      string
		expected []string
	}{
		{
			src:      `"hello ${noun}"`,
			expected: []string{"noun"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			expr, diag := json.ParseExpression([]byte(tt.src), "")
			if diag.HasErrors() {
				require.NoError(t, diag)
			}

			attr := NewAttribute(&hcl.Attribute{
				Name:      "test",
				Expr:      expr,
				Range:     hcl.Range{},
				NameRange: hcl.Range{},
			}, context.NewContext(&hcl.EvalContext{}, nil), "", types.Metadata{}, Reference{}, "", nil)

			refs := attr.AllReferences()
			humanRefs := make([]string, 0, len(refs))
			for _, ref := range refs {
				humanRefs = append(humanRefs, ref.HumanReadable())
			}

			require.ElementsMatch(t, tt.expected, humanRefs)
		})
	}
}
