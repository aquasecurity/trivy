package terraform

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
)

func Test_DeterministicResults(t *testing.T) {
	fsys := testutil.CreateFS(t, map[string]string{
		"first.tf": `
resource "aws_s3_bucket" "test" {
  for_each = other.thing
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

	for i := 0; i < 100; i++ {
		results, err := scanFS(fsys, ".",
			rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
			rego.WithPolicyNamespaces("user"),
		)
		require.NoError(t, err)
		require.Len(t, results.GetFailed(), 2)
	}
}
