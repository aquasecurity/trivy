package terraform

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

var exampleRule = scan.Rule{
	Provider:  providers.AWSProvider,
	Service:   "service",
	ShortCode: "abc123",
	AVDID:     "AWS-ABC-123",
	Aliases:   []string{"aws-other-abc123"},
	Severity:  severity.High,
	CustomChecks: scan.CustomChecks{
		Terraform: &scan.TerraformCustomCheck{
			RequiredLabels: []string{"bad"},
			Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results scan.Results) {
				if attr, _ := resourceBlock.GetNestedAttribute("secure_settings.enabled"); attr.IsNotNil() {
					if attr.IsFalse() {
						results.Add("example problem", attr)
					}
				} else {
					attr := resourceBlock.GetAttribute("secure")
					if attr.IsNil() {
						results.Add("example problem", resourceBlock)
					}
					if attr.IsFalse() {
						results.Add("example problem", attr)
					}
				}
				return
			},
		},
	},
}

func Test_IgnoreAll(t *testing.T) {

	var testCases = []struct {
		name         string
		inputOptions string
		assertLength int
	}{
		{
			name: "IgnoreAll",
			inputOptions: `
resource "bad" "my-rule" {
    secure = false // tfsec:ignore:*
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreLineAboveTheBlock",
			inputOptions: `
// tfsec:ignore:*
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreLineAboveTheBlockMatchingParamBool",
			inputOptions: `
// tfsec:ignore:*[secure=false]
resource "bad" "my-rule" {
   secure = false
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreLineAboveTheBlockNotMatchingParamBool",
			inputOptions: `
// tfsec:ignore:*[secure=true]
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 1,
		},
		{
			name: "IgnoreLineAboveTheBlockMatchingParamString",
			inputOptions: `
// tfsec:ignore:*[name=myrule]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreLineAboveTheBlockNotMatchingParamString",
			inputOptions: `
// tfsec:ignore:*[name=myrule2]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false 
}
`,
			assertLength: 1,
		},
		{
			name: "IgnoreLineAboveTheBlockMatchingParamInt",
			inputOptions: `
// tfsec:ignore:*[port=123]
resource "bad" "my-rule" {
   secure = false
   port = 123
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreLineAboveTheBlockNotMatchingParamInt",
			inputOptions: `
// tfsec:ignore:*[port=456]
resource "bad" "my-rule" {
   secure = false 
   port = 123
}
`,
			assertLength: 1,
		},
		{
			name: "IgnoreLineStackedAboveTheBlock",
			inputOptions: `
// tfsec:ignore:*
// tfsec:ignore:a
// tfsec:ignore:b
// tfsec:ignore:c
// tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreLineStackedAboveTheBlockWithoutMatch",
			inputOptions: `
#tfsec:ignore:*

#tfsec:ignore:x
#tfsec:ignore:a
#tfsec:ignore:b
#tfsec:ignore:c
#tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 1,
		},
		{
			name: "IgnoreLineStackedAboveTheBlockWithHashesWithoutSpaces",
			inputOptions: `
#tfsec:ignore:*
#tfsec:ignore:a
#tfsec:ignore:b
#tfsec:ignore:c
#tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreLineStackedAboveTheBlockWithoutSpaces",
			inputOptions: `
//tfsec:ignore:*
//tfsec:ignore:a
//tfsec:ignore:b
//tfsec:ignore:c
//tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreLineAboveTheLine",
			inputOptions: `
resource "bad" "my-rule" {
	# tfsec:ignore:aws-service-abc123
    secure = false
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreWithExpDateIfDateBreachedThenDontIgnore",
			inputOptions: `
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:aws-service-abc123:exp:2000-01-02
}
`,
			assertLength: 1,
		},
		{
			name: "IgnoreWithExpDateIfDateNotBreachedThenIgnoreIgnore",
			inputOptions: `
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:aws-service-abc123:exp:2221-01-02
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreWithExpDateIfDateInvalidThenDropTheIgnore",
			inputOptions: `
resource "bad" "my-rule" {
   secure = false # tfsec:ignore:aws-service-abc123:exp:2221-13-02
}
`,
			assertLength: 1,
		},
		{
			name: "IgnoreAboveResourceBlockWithExpDateIfDateNotBreachedThenIgnoreIgnore",
			inputOptions: `
#tfsec:ignore:aws-service-abc123:exp:2221-01-02
resource "bad" "my-rule" {
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreAboveResourceBlockWithExpDateAndMultipleIgnoresIfDateNotBreachedThenIgnoreIgnore",
			inputOptions: `
# tfsec:ignore:aws-service-abc123:exp:2221-01-02
resource "bad" "my-rule" {
	
}
`,
			assertLength: 0,
		},
		{
			name: "IgnoreForImpliedIAMResource",
			inputOptions: `
terraform {
  required_version = "~> 1.1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.48"
    }
  }
}

# Retrieve an IAM group defined outside of this Terraform config.

# tfsec:ignore:aws-iam-enforce-mfa
data "aws_iam_group" "externally_defined_group" {
  group_name = "group-name" # tfsec:ignore:aws-iam-enforce-mfa
}

# Create an IAM policy and attach it to the group.

# tfsec:ignore:aws-iam-enforce-mfa
resource "aws_iam_policy" "test_policy" {
  name   = "test-policy"                                 # tfsec:ignore:aws-iam-enforce-mfa
  policy = data.aws_iam_policy_document.test_policy.json # tfsec:ignore:aws-iam-enforce-mfa
}

# tfsec:ignore:aws-iam-enforce-mfa
resource "aws_iam_group_policy_attachment" "test_policy_attachment" {
  group      = data.aws_iam_group.externally_defined_group.group_name # tfsec:ignore:aws-iam-enforce-mfa
  policy_arn = aws_iam_policy.test_policy.arn                         # tfsec:ignore:aws-iam-enforce-mfa
}

# tfsec:ignore:aws-iam-enforce-mfa
data "aws_iam_policy_document" "test_policy" {
  statement {
    sid = "PublishToCloudWatch" # tfsec:ignore:aws-iam-enforce-mfa
    actions = [
      "cloudwatch:PutMetricData", # tfsec:ignore:aws-iam-enforce-mfa
    ]
    resources = ["*"] # tfsec:ignore:aws-iam-enforce-mfa
  }
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreAll",
			inputOptions: `
resource "bad" "my-rule" {
    secure = false // trivy:ignore:*
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreLineAboveTheBlock",
			inputOptions: `
// trivy:ignore:*
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreLineAboveTheBlockMatchingParamBool",
			inputOptions: `
// trivy:ignore:*[secure=false]
resource "bad" "my-rule" {
   secure = false
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreLineAboveTheBlockNotMatchingParamBool",
			inputOptions: `
// trivy:ignore:*[secure=true]
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 1,
		},
		{
			name: "TrivyIgnoreLineAboveTheBlockMatchingParamString",
			inputOptions: `
// trivy:ignore:*[name=myrule]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreLineAboveTheBlockNotMatchingParamString",
			inputOptions: `
// trivy:ignore:*[name=myrule2]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false 
}
`,
			assertLength: 1,
		},
		{
			name: "TrivyIgnoreLineAboveTheBlockMatchingParamInt",
			inputOptions: `
// trivy:ignore:*[port=123]
resource "bad" "my-rule" {
   secure = false
   port = 123
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreLineAboveTheBlockNotMatchingParamInt",
			inputOptions: `
// trivy:ignore:*[port=456]
resource "bad" "my-rule" {
   secure = false 
   port = 123
}
`,
			assertLength: 1,
		},
		{
			name: "ignore by nested attribute",
			inputOptions: `
// trivy:ignore:*[secure_settings.enabled=false]
resource "bad" "my-rule" {
  secure_settings {
    enabled = false
  }
}
`,
			assertLength: 0,
		},
		{
			name: "ignore by nested attribute of another type",
			inputOptions: `
// trivy:ignore:*[secure_settings.enabled=1]
resource "bad" "my-rule" {
  secure_settings {
    enabled = false
  }
}
`,
			assertLength: 1,
		},
		{
			name: "ignore by non-existent nested attribute",
			inputOptions: `
// trivy:ignore:*[secure_settings.rule=myrule]
resource "bad" "my-rule" {
  secure_settings {
    enabled = false
  }
}
`,
			assertLength: 1,
		},
		{
			name: "ignore resource with `for_each` meta-argument",
			inputOptions: `
// trivy:ignore:*[secure=false]
resource "bad" "my-rule" {
  for_each = toset(["false", "true", "false"])
  secure   = each.key
}
`,
			assertLength: 0,
		},
		{
			name: "ignore by dynamic block value",
			inputOptions: `
// trivy:ignore:*[secure_settings.enabled=false]
resource "bad" "my-rule" {
  dynamic "secure_settings" {
    for_each = ["false", "true"]
    content {
      enabled = secure_settings.value
    }
  }
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreLineStackedAboveTheBlock",
			inputOptions: `
// trivy:ignore:*
// trivy:ignore:a
// trivy:ignore:b
// trivy:ignore:c
// trivy:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreLineStackedAboveTheBlockWithoutMatch",
			inputOptions: `
#trivy:ignore:*

#trivy:ignore:x
#trivy:ignore:a
#trivy:ignore:b
#trivy:ignore:c
#trivy:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 1,
		},
		{
			name: "TrivyIgnoreLineStackedAboveTheBlockWithHashesWithoutSpaces",
			inputOptions: `
#trivy:ignore:*
#trivy:ignore:a
#trivy:ignore:b
#trivy:ignore:c
#trivy:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreLineStackedAboveTheBlockWithoutSpaces",
			inputOptions: `
//trivy:ignore:*
//trivy:ignore:a
//trivy:ignore:b
//trivy:ignore:c
//trivy:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreLineAboveTheLine",
			inputOptions: `
resource "bad" "my-rule" {
	# trivy:ignore:aws-service-abc123
    secure = false
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreWithExpDateIfDateBreachedThenDontIgnore",
			inputOptions: `
resource "bad" "my-rule" {
    secure = false # trivy:ignore:aws-service-abc123:exp:2000-01-02
}
`,
			assertLength: 1,
		},
		{
			name: "TrivyIgnoreWithExpDateIfDateNotBreachedThenIgnoreIgnore",
			inputOptions: `
resource "bad" "my-rule" {
    secure = false # trivy:ignore:aws-service-abc123:exp:2221-01-02
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreWithExpDateIfDateInvalidThenDropTheIgnore",
			inputOptions: `
resource "bad" "my-rule" {
   secure = false # trivy:ignore:aws-service-abc123:exp:2221-13-02
}
`,
			assertLength: 1,
		},
		{
			name: "TrivyIgnoreAboveResourceBlockWithExpDateIfDateNotBreachedThenIgnoreIgnore",
			inputOptions: `
#trivy:ignore:aws-service-abc123:exp:2221-01-02
resource "bad" "my-rule" {
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreAboveResourceBlockWithExpDateAndMultipleIgnoresIfDateNotBreachedThenIgnoreIgnore",
			inputOptions: `
# trivy:ignore:aws-service-abc123:exp:2221-01-02
resource "bad" "my-rule" {
	
}
`,
			assertLength: 0,
		},
		{
			name: "TrivyIgnoreForImpliedIAMResource",
			inputOptions: `
terraform {
  required_version = "~> 1.1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.48"
    }
  }
}

# Retrieve an IAM group defined outside of this Terraform config.

# trivy:ignore:aws-iam-enforce-mfa
data "aws_iam_group" "externally_defined_group" {
  group_name = "group-name" # trivy:ignore:aws-iam-enforce-mfa
}

# Create an IAM policy and attach it to the group.

# trivy:ignore:aws-iam-enforce-mfa
resource "aws_iam_policy" "test_policy" {
  name   = "test-policy"                                 # trivy:ignore:aws-iam-enforce-mfa
  policy = data.aws_iam_policy_document.test_policy.json # trivy:ignore:aws-iam-enforce-mfa
}

# trivy:ignore:aws-iam-enforce-mfa
resource "aws_iam_group_policy_attachment" "test_policy_attachment" {
  group      = data.aws_iam_group.externally_defined_group.group_name # trivy:ignore:aws-iam-enforce-mfa
  policy_arn = aws_iam_policy.test_policy.arn                         # trivy:ignore:aws-iam-enforce-mfa
}

# trivy:ignore:aws-iam-enforce-mfa
data "aws_iam_policy_document" "test_policy" {
  statement {
    sid = "PublishToCloudWatch" # trivy:ignore:aws-iam-enforce-mfa
    actions = [
      "cloudwatch:PutMetricData", # trivy:ignore:aws-iam-enforce-mfa
    ]
    resources = ["*"] # trivy:ignore:aws-iam-enforce-mfa
  }
}
`,
			assertLength: 0,
		},
	}

	reg := rules.Register(exampleRule)
	defer rules.Deregister(reg)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := scanHCL(t, tc.inputOptions)
			assert.Len(t, results.GetFailed(), tc.assertLength)
		})
	}
}

func Test_IgnoreByWorkspace(t *testing.T) {
	reg := rules.Register(exampleRule)
	defer rules.Deregister(reg)

	tests := []struct {
		name           string
		src            string
		expectedFailed int
	}{
		{
			name: "with expiry and workspace",
			src: `# tfsec:ignore:aws-service-abc123:exp:2221-01-02:ws:testworkspace
resource "bad" "my-rule" {}`,
			expectedFailed: 0,
		},
		{
			name: "bad workspace",
			src: `# tfsec:ignore:aws-service-abc123:exp:2221-01-02:ws:otherworkspace
resource "bad" "my-rule" {}`,
			expectedFailed: 1,
		},
		{
			name: "with expiry and workspace, trivy prefix",
			src: `# trivy:ignore:aws-service-abc123:exp:2221-01-02:ws:testworkspace
resource "bad" "my-rule" {}`,
			expectedFailed: 0,
		},
		{
			name: "bad workspace, trivy prefix",
			src: `# trivy:ignore:aws-service-abc123:exp:2221-01-02:ws:otherworkspace
resource "bad" "my-rule" {}`,
			expectedFailed: 1,
		},
		{
			name: "workspace with wildcard",
			src: `# tfsec:ignore:*:ws:test* 
resource "bad" "my-rule" {}`,
			expectedFailed: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := scanHCLWithWorkspace(t, tt.src, "testworkspace")
			assert.Len(t, results.GetFailed(), tt.expectedFailed)
		})
	}
}

func Test_IgnoreInline(t *testing.T) {
	reg := rules.Register(exampleRule)
	defer rules.Deregister(reg)

	results := scanHCL(t, fmt.Sprintf(`
	resource "bad" "sample" {
		  secure = false # tfsec:ignore:%s
	}
	  `, exampleRule.LongID()))
	assert.Empty(t, results.GetFailed())
}

func Test_IgnoreWithAliasCodeStillIgnored(t *testing.T) {
	reg := rules.Register(exampleRule)
	defer rules.Deregister(reg)

	results := scanHCLWithWorkspace(t, `
# tfsec:ignore:aws-other-abc123
resource "bad" "my-rule" {
	
}
`, "testworkspace")
	assert.Empty(t, results.GetFailed())
}

func Test_TrivyIgnoreWithAliasCodeStillIgnored(t *testing.T) {
	reg := rules.Register(exampleRule)
	defer rules.Deregister(reg)

	results := scanHCLWithWorkspace(t, `
# trivy:ignore:aws-other-abc123
resource "bad" "my-rule" {
	
}
`, "testworkspace")
	assert.Empty(t, results.GetFailed())
}

func Test_TrivyIgnoreInline(t *testing.T) {
	reg := rules.Register(exampleRule)
	defer rules.Deregister(reg)

	results := scanHCL(t, fmt.Sprintf(`
	resource "bad" "sample" {
		  secure = false # trivy:ignore:%s
	}
	  `, exampleRule.LongID()))
	assert.Empty(t, results.GetFailed())
}

func Test_IgnoreInlineByAVDID(t *testing.T) {
	testCases := []struct {
		input string
	}{
		{
			input: `
	resource "bad" "sample" {
		  secure = false # tfsec:ignore:%s
	}
	  `,
		},
		{
			input: `
	resource "bad" "sample" {
		  secure = false # trivy:ignore:%s
	}
	  `,
		},
	}

	for _, tc := range testCases {
		tc := tc
		for _, id := range []string{exampleRule.AVDID, strings.ToLower(exampleRule.AVDID), exampleRule.ShortCode, exampleRule.LongID()} {
			id := id
			t.Run("", func(t *testing.T) {
				reg := rules.Register(exampleRule)
				defer rules.Deregister(reg)
				results := scanHCL(t, fmt.Sprintf(tc.input, id))
				assert.Empty(t, results.GetFailed())
			})
		}
	}
}

func TestIgnoreRemoteTerraformResource(t *testing.T) {

	fsys := testutil.CreateFS(t, map[string]string{
		"main.tf": `module "bucket" {
  source = "git::https://github.com/test/bucket"
}`,
		".terraform/modules/modules.json": `{
    "Modules": [
        { "Key": "", "Source": "", "Dir": "." },
        {
            "Key": "bucket",
            "Source": "git::https://github.com/test/bucket",
            "Dir": ".terraform/modules/bucket"
        }
    ]
}
`,
		".terraform/modules/bucket/main.tf": `
# trivy:ignore:test-0001
resource "aws_s3_bucket" "test" {
  bucket = ""
}
`,
	})

	check := `# METADATA
# title: Test
# custom:
#   id: test-0001
#   avdid: test-0001

package user.test0001

deny[res] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == ""
	res := result.new("Empty bucket name!", bucket)
}`

	localScanner := New(
		options.ScannerWithEmbeddedPolicies(false),
		options.ScannerWithEmbeddedLibraries(true),
		options.ScannerWithRegoOnly(true),
		options.ScannerWithPolicyNamespaces("user"),
		options.ScannerWithPolicyReader(strings.NewReader(check)),
		ScannerWithDownloadsAllowed(false),
		ScannerWithSkipCachedModules(true),
	)
	results, err := localScanner.ScanFS(context.TODO(), fsys, ".")
	require.NoError(t, err)
	assert.Empty(t, results.GetFailed())
}
