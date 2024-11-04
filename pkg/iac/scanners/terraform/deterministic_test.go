package terraform

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/executor"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_DeterministicResults(t *testing.T) {
	fsys := testutil.CreateFS(t, map[string]string{
		"first.tf": `
resource "aws_s3_bucket" "test" {
  for_each = other.thing

  bucket = ""
}
		`,
		"second.tf": `
resource "other" "thing" {
	for_each = local.list
}
		`,
		"third.tf": `
locals {
	list = {
		a = 1,
		b = 2,
	}
}
		`,
	})

	regoScanner := rego.NewScanner(
		iacTypes.SourceCloud,
		rego.WithEmbeddedLibraries(true),
		rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
		rego.WithPolicyNamespaces("user"),
	)

	require.NoError(t, regoScanner.LoadPolicies(fsys))

	for i := 0; i < 100; i++ {
		p := parser.New(fsys, "", parser.OptionStopOnHCLError(true))
		err := p.ParseFS(context.TODO(), ".")
		require.NoError(t, err)
		modules, _, err := p.EvaluateAll(context.TODO())
		require.NoError(t, err)

		results, err := executor.New(
			executor.OptionWithRegoScanner(regoScanner),
			executor.OptionWithRegoOnly(true),
		).Execute(modules)
		require.NoError(t, err)

		require.Len(t, results.GetFailed(), 2)
	}
}
