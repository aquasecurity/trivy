package terraform

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
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
			input: `{foo = 1 == 1 ? true : data.aws_ami.ubuntu.most_recent}`,
			refs:  []string{"data.aws_ami.ubuntu.most_recent"},
		},
		{
			input: `[var.foo, var.bar]`,
			refs:  []string{"variable.foo", "variable.bar"},
		},
	}

	for _, test := range cases {
		t.Run(test.input, func(t *testing.T) {
			ctx := context.NewContext(&hcl.EvalContext{}, nil)

			exp, diags := hclsyntax.ParseExpression([]byte(test.input), "", hcl.Pos{Line: 1, Column: 1})
			if diags != nil && diags.HasErrors() {
				t.Fatal(diags.Error())
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
