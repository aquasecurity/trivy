package cloudformation

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
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

	scanner := New(options.ScannerWithPolicyDirs("rules"), options.ScannerWithRegoOnly(true))

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
		CustomChecks: scan.CustomChecks{
			Terraform: (*scan.TerraformCustomCheck)(nil),
		},
		RegoPackage: "data.builtin.dockerfile.DS006",
		Frameworks:  map[framework.Framework][]string{},
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
