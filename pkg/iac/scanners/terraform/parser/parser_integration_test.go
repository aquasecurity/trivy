package parser

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
)

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
	require.NoError(t, parser.ParseFS(t.Context(), "code"))

	modules, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 2)
}
