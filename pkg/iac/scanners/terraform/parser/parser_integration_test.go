package parser

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
)

func Test_DefaultRegistry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	fsys := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
module "registry" {
	source = "terraform-aws-modules/vpc/aws"
}
`,
	})

	parser := New(fsys, "", OptionStopOnHCLError(true), OptionWithSkipCachedModules(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))

	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)
	require.Len(t, modules, 2)
}

func Test_SpecificRegistry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	fsys := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
module "registry" {
	source = "registry.terraform.io/terraform-aws-modules/vpc/aws"
}
`,
	})

	parser := New(fsys, "", OptionStopOnHCLError(true), OptionWithSkipCachedModules(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))

	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)
	require.Len(t, modules, 2)
}

func Test_ModuleWithPessimisticVersionConstraint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	fsys := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
module "registry" {
	source = "registry.terraform.io/terraform-aws-modules/s3-bucket/aws"
	bucket = "my-s3-bucket"
	version = "~> 3.1"
}
`,
	})

	parser := New(fsys, "", OptionStopOnHCLError(true), OptionWithSkipCachedModules(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))

	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)
	require.Len(t, modules, 2)
}

func Test_ModuleInSubdir(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	fsys := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
module "object" {
	source = "git::https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git//modules/object?ref=v4.1.2"

}`,
	})

	parser := New(fsys, "", OptionStopOnHCLError(true), OptionWithSkipCachedModules(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))

	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)
	require.Len(t, modules, 2)
}
