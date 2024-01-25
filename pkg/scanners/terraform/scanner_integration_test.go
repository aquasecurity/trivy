package terraform

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/trivy-iac/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ScanRemoteModule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "my-s3-bucket"
}
`,
		"/rules/bucket_name.rego": `
# METADATA
# schemas:
# - input: schema.input
# custom:
#   avd_id: AVD-AWS-0001
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: s3
#           provider: aws
package defsec.test.aws1
deny[res] {
  bucket := input.aws.s3.buckets[_]
  bucket.name.value == ""
  res := result.new("The name of the bucket must not be empty", bucket)
}`,
	})

	debugLog := bytes.NewBuffer([]byte{})

	scanner := New(
		options.ScannerWithDebug(debugLog),
		options.ScannerWithPolicyFilesystem(fs),
		options.ScannerWithPolicyDirs("rules"),
		options.ScannerWithEmbeddedPolicies(false),
		options.ScannerWithEmbeddedLibraries(false),
		options.ScannerWithRegoOnly(true),
		ScannerWithAllDirectories(true),
		ScannerWithSkipCachedModules(true),
	)

	results, err := scanner.ScanFS(context.TODO(), fs, ".")
	require.NoError(t, err)

	assert.Len(t, results.GetPassed(), 1)

	if t.Failed() {
		fmt.Printf("Debug logs:\n%s\n", debugLog.String())
	}
}

func Test_ScanChildUseRemoteModule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `
module "this" {
	source = "./modules/s3"
	bucket = "my-s3-bucket"
}
`,
		"modules/s3/main.tf": `
variable "bucket" {
	type = string
}

module "s3_bucket" {
  source = "github.com/terraform-aws-modules/terraform-aws-s3-bucket?ref=v3.15.1"
  bucket = var.bucket
}
`,
		"rules/bucket_name.rego": `
# METADATA
# schemas:
# - input: schema.input
# custom:
#   avd_id: AVD-AWS-0001
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: s3
#           provider: aws
package defsec.test.aws1
deny[res] {
  bucket := input.aws.s3.buckets[_]
  bucket.name.value == ""
  res := result.new("The name of the bucket must not be empty", bucket)
}`,
	})

	debugLog := bytes.NewBuffer([]byte{})

	scanner := New(
		options.ScannerWithDebug(debugLog),
		options.ScannerWithPolicyFilesystem(fs),
		options.ScannerWithPolicyDirs("rules"),
		options.ScannerWithEmbeddedPolicies(false),
		options.ScannerWithEmbeddedLibraries(false),
		options.ScannerWithRegoOnly(true),
		ScannerWithAllDirectories(true),
		ScannerWithSkipCachedModules(true),
	)

	results, err := scanner.ScanFS(context.TODO(), fs, ".")
	require.NoError(t, err)

	assert.Len(t, results.GetPassed(), 1)

	if t.Failed() {
		fmt.Printf("Debug logs:\n%s\n", debugLog.String())
	}
}
