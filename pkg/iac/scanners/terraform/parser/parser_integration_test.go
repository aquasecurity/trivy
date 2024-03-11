package parser

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/stretchr/testify/require"
)

func Test_DefaultRegistry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
module "registry" {
	source = "terraform-aws-modules/vpc/aws"
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true), OptionWithSkipCachedModules(true))
	if err := parser.ParseFS(context.TODO(), "code"); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)
	require.Len(t, modules, 2)
}

func Test_SpecificRegistry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
module "registry" {
	source = "registry.terraform.io/terraform-aws-modules/vpc/aws"
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true), OptionWithSkipCachedModules(true))
	if err := parser.ParseFS(context.TODO(), "code"); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)
	require.Len(t, modules, 2)
}
