package terraform

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
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

	for i := 0; i < 100; i++ {
		results, err := scanFS(fsys, ".")
		require.NoError(t, err)
		require.Len(t, results.GetFailed(), 2)
	}
}
