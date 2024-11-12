package cloudformation

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

func Test_BasicScan(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"/code/main.yaml": `---
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: public-bucket

`,
		"/rules/rule.rego": `package builtin.dockerfile.DS006

__rego_metadata__ := {
	"id": "DS006",
	"avd_id": "AVD-DS-0006",
	"title": "COPY '--from' referring to the current image",
	"short_code": "no-self-referencing-copy-from",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
	"recommended_actions": "Change the '--from' so that it will not refer to itself",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "defsec", "subtypes": [{"service": "s3", "provider": "aws"}]}],
}

deny[res] {
	res := {
		"msg": "oh no",
		"filepath": "code/main.yaml",
		"startline": 6,
		"endline": 6,
	}
}

`,
	})

	scanner := New(rego.WithPolicyDirs("rules"))

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	assert.Equal(t, scan.Rule{
		AVDID:          "AVD-DS-0006",
		Aliases:        []string{"DS006"},
		ShortCode:      "no-self-referencing-copy-from",
		Summary:        "COPY '--from' referring to the current image",
		Explanation:    "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
		Impact:         "",
		Resolution:     "Change the '--from' so that it will not refer to itself",
		Provider:       "cloud",
		Service:        "general",
		Links:          []string{"https://docs.docker.com/develop/develop-images/multistage-build/"},
		Severity:       "CRITICAL",
		Terraform:      &scan.EngineMetadata{},
		CloudFormation: &scan.EngineMetadata{},
		RegoPackage:    "data.builtin.dockerfile.DS006",
		Frameworks: map[framework.Framework][]string{
			framework.Default: {},
		},
	}, results.GetFailed()[0].Rule())

	failure := results.GetFailed()[0]
	actualCode, err := failure.GetCode()
	require.NoError(t, err)
	for i := range actualCode.Lines {
		actualCode.Lines[i].Highlighted = ""
	}
	assert.Equal(t, []scan.Line{
		{
			Number:     6,
			Content:    "      BucketName: public-bucket",
			IsCause:    true,
			FirstCause: true,
			LastCause:  true,
			Annotation: "",
		},
	}, actualCode.Lines)
}

const bucketNameCheck = `# METADATA
# title: "test rego"
# scope: package
# schemas:
# - input: schema["cloud"]
# custom:
#   id: AVD-AWS-001
#   avd_id: AVD-AWS-001
#   provider: aws
#   service: s3
#   severity: LOW
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: s3
#           provider: aws
package user.aws.aws001

deny[res] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "test-bucket"
	res := result.new("Denied", bucket.name)
}

deny[res] {
	bucket := input.aws.s3.buckets[_]
	algo := bucket.encryption.algorithm
	algo.value == "AES256"
	res := result.new("Denied", algo)
}
`

func TestIgnore(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		ignored int
	}{
		{
			name: "without ignore",
			src: `---
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: test-bucket
`,
			ignored: 0,
		},
		{
			name: "rule before resource",
			src: `---
Resources:
#trivy:ignore:AVD-AWS-001
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: test-bucket
`,
			ignored: 1,
		},
		{
			name: "rule before property",
			src: `---
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
#trivy:ignore:AVD-AWS-001
      BucketName: test-bucket
`,
			ignored: 1,
		},
		{
			name: "rule on the same line with the property",
			src: `---
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: test-bucket  #trivy:ignore:AVD-AWS-001
`,
			ignored: 1,
		},
		{
			name: "rule on the same line with the nested property",
			src: `---
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: test-bucket
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256 #trivy:ignore:AVD-AWS-001
`,
			ignored: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := testutil.CreateFS(t, map[string]string{
				"/code/main.yaml": tt.src,
			})

			scanner := New(
				rego.WithEmbeddedPolicies(false),
				rego.WithPolicyReader(strings.NewReader(bucketNameCheck)),
				rego.WithPolicyNamespaces("user"),
			)

			results, err := scanner.ScanFS(context.TODO(), fsys, "code")
			require.NoError(t, err)

			if tt.ignored == 0 {
				require.Len(t, results.GetFailed(), 1)
			} else {
				assert.Len(t, results.GetIgnored(), tt.ignored)
			}
		})
	}
}
