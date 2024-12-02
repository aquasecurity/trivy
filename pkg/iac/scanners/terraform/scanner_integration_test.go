package terraform

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
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
	})

	scanner := New(
		rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
		rego.WithPolicyNamespaces("user"),
		rego.WithEmbeddedPolicies(false),
		rego.WithEmbeddedLibraries(false),
		ScannerWithAllDirectories(true),
		ScannerWithSkipCachedModules(true),
	)

	results, err := scanner.ScanFS(context.TODO(), fs, ".")
	require.NoError(t, err)

	assert.Len(t, results.GetPassed(), 1)
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
	})

	scanner := New(
		rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
		rego.WithPolicyNamespaces("user"),
		rego.WithEmbeddedPolicies(false),
		rego.WithEmbeddedLibraries(false),
		ScannerWithAllDirectories(true),
		ScannerWithSkipCachedModules(true),
	)

	results, err := scanner.ScanFS(context.TODO(), fs, ".")
	require.NoError(t, err)

	assert.Len(t, results.GetPassed(), 1)
}

func Test_OptionWithSkipDownloaded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	fs := testutil.CreateFS(t, map[string]string{
		"test/main.tf": `
module "s3-bucket" {
  source   = "terraform-aws-modules/s3-bucket/aws"
  version = "3.14.0"
  bucket = "mybucket"
  create_bucket = true
}
`,
		// creating our own rule for the reliability of the test
		"/rules/test.rego": `
package defsec.abcdefg
__rego_input__ := {
	"combine": false,
	"selector": [{"type": "defsec", "subtypes": [{"service": "s3", "provider": "aws"}]}],
}
deny[cause] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "mybucket"
	cause := bucket.name
}`,
	})

	t.Run("without skip", func(t *testing.T) {
		scanner := New(
			ScannerWithSkipCachedModules(true),
			rego.WithPolicyDirs("rules"),
			rego.WithEmbeddedPolicies(false),
			rego.WithEmbeddedLibraries(true),
		)
		results, err := scanner.ScanFS(context.TODO(), fs, "test")
		require.NoError(t, err)

		assert.Len(t, results, 1)
		assert.Len(t, results.GetFailed(), 1)
	})

	t.Run("with skip", func(t *testing.T) {
		scanner := New(
			ScannerWithSkipDownloaded(true),
			ScannerWithSkipCachedModules(true),
			rego.WithPolicyDirs("rules"),
			rego.WithEmbeddedPolicies(false),
			rego.WithEmbeddedLibraries(true),
		)
		results, err := scanner.ScanFS(context.TODO(), fs, "test")
		require.NoError(t, err)

		assert.Len(t, results, 1)
		assert.Len(t, results.GetIgnored(), 1)
	})
}

func Test_OptionWithSkipDownloadedIAMDocument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	fs := testutil.CreateFS(t, map[string]string{
		"test/main.tf": `
module "karpenter" {
  source  = "terraform-aws-modules/eks/aws//modules/karpenter"
  version = "19.21.0"
  cluster_name           = "test"
  irsa_oidc_provider_arn = "example"
}
`,
		// creating our own rule for the reliability of the test
		"/rules/test.rego": `
package defsec.abcdefg
__rego_input__ := {
	"combine": false,
	"selector": [{"type": "defsec", "subtypes": [{"service": "iam", "provider": "aws"}]}],
}
allows_permission(statements, permission, effect) {
	statement := statements[_]
	statement.Effect == effect
	action = statement.Action[_]
	action == permission
}
deny[res] {
	policy := input.aws.iam.policies[_]
	value = json.unmarshal(policy.document.value)
	statements = value.Statement
	not allows_permission(statements, "iam:PassRole", "Deny")
	allows_permission(statements, "iam:PassRole", "Allow")
	res = result.new("IAM policy allows 'iam:PassRole' action", policy.document)
}
`,
	})

	scanner := New(
		ScannerWithSkipDownloaded(true),
		ScannerWithSkipCachedModules(true),
		rego.WithPolicyDirs("rules"),
		rego.WithEmbeddedLibraries(true),
		rego.WithEmbeddedPolicies(false),
	)
	results, err := scanner.ScanFS(context.TODO(), fs, "test")
	require.NoError(t, err)
	assert.Len(t, results, 1)

	ignored := results.GetIgnored()
	assert.Len(t, ignored, 1)
	assert.NotNil(t, ignored[0].Metadata().Parent())
}
