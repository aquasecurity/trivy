package terraform

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
)

func Test_IgnoreAll(t *testing.T) {

	var testCases = []struct {
		name         string
		source       string
		assertLength int
	}{
		{
			name: "inline rule ignore all checks",
			source: `resource "aws_s3_bucket" "test" {
  bucket = "" // %s:ignore:*
}`,
			assertLength: 0,
		},
		{
			name: "rule above block ignore all checks",
			source: `// %s:ignore:*
resource "aws_s3_bucket" "test" {}`,
			assertLength: 0,
		},
		{
			name: "rule above block with boolean parameter",
			source: `// %s:ignore:*[object_lock_enabled=false]
resource "aws_s3_bucket" "test" {
  object_lock_enabled = false
}`,
			assertLength: 0,
		},
		{
			name: "rule above block with non-matching boolean parameter",
			source: `// %s:ignore:*[object_lock_enabled=false]
resource "aws_s3_bucket" "test" {
  object_lock_enabled = true
}`,
			assertLength: 1,
		},
		{
			name: "rule above block with string parameter",
			source: `// %s:ignore:*[acl=private]
resource "aws_s3_bucket" "test" {
    acl = "private"
}`,
			assertLength: 0,
		},
		{
			name: "rule above block with non-matching string parameter",
			source: `// %s:ignore:*[acl=private]
resource "aws_s3_bucket" "test" {
    acl = "public"
}`,
			assertLength: 1,
		},
		{
			name: "rule above block with int parameter",
			source: `// %s:ignore:*[some_int=123]
resource "aws_s3_bucket" "test" {
   some_int = 123
}`,
			assertLength: 0,
		},
		{
			name: "rule above block with non-matching int parameter",
			source: `// %s:ignore:*[some_int=456]
resource "aws_s3_bucket" "test" {
   some_int = 123
}`,
			assertLength: 1,
		},
		{
			name: "stacked rules above block",
			source: `// %s:ignore:*
// %s:ignore:a
// %s:ignore:b
// %s:ignore:c
// %s:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "stacked rules above block without a match",
			source: `#%s:ignore:*

#%s:ignore:x
#%s:ignore:a
#%s:ignore:b
#%s:ignore:c
#%s:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 1,
		},
		{
			name: "stacked rules above block without spaces between '#' comments",
			source: `#%s:ignore:*
#%s:ignore:a
#%s:ignore:b
#%s:ignore:c
#%s:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "stacked rules above block without spaces between '//' comments",
			source: `//%s:ignore:*
//%s:ignore:a
//%s:ignore:b
//%s:ignore:c
//%s:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "rule above the finding",
			source: `resource "aws_s3_bucket" "test" {
	# %s:ignore:aws-s3-non-empty-bucket
    bucket = ""
}`,
			assertLength: 0,
		},
		{
			name: "rule with breached expiration date",
			source: `resource "aws_s3_bucket" "test" {
    bucket = "" # %s:ignore:aws-s3-non-empty-bucket:exp:2000-01-02
}`,
			assertLength: 1,
		},
		{
			name: "rule with unbreached expiration date",
			source: `resource "aws_s3_bucket" "test" {
    bucket = "" # %s:ignore:aws-s3-non-empty-bucket:exp:2221-01-02
}`,
			assertLength: 0,
		},
		{
			name: "rule with invalid expiration date",
			source: `resource "aws_s3_bucket" "test" {
   bucket = "" # %s:ignore:aws-s3-non-empty-bucket:exp:2221-13-02
}`,
			assertLength: 1,
		},
		{
			name: "rule above block with unbreached expiration date",
			source: `#%s:ignore:aws-s3-non-empty-bucket:exp:2221-01-02
resource "aws_s3_bucket" "test" {}`,
			assertLength: 0,
		},
		{
			name: "trivy inline rule ignore all checks",
			source: `resource "aws_s3_bucket" "test" {
    bucket = "" // %s:ignore:*
}`,
			assertLength: 0,
		},
		{
			name: "ignore by nested attribute",
			source: `// %s:ignore:*[versioning.enabled=false]
resource "aws_s3_bucket" "test" {
  versioning {
    enabled = false
  }
}`,
			assertLength: 0,
		},
		{
			name: "ignore by nested attribute of another type",
			source: `// %s:ignore:*[versioning.enabled=1]
resource "aws_s3_bucket" "test" {
  versioning {
    enabled = false
  }
}`,
			assertLength: 1,
		},
		{
			name: "ignore by non-existent nested attribute",
			source: `// %s:ignore:*[versioning.target=foo]
resource "aws_s3_bucket" "test" {
  versioning {
    enabled = false
  }
}`,
			assertLength: 1,
		},
		{
			name: "ignore resource with `for_each` meta-argument",
			source: `// %s:ignore:*[acl=public]
resource "aws_s3_bucket" "test" {
  for_each = toset(["private", "public"])
  acl = each.value
}`,
			assertLength: 1,
		},
		{
			name: "ignore by dynamic block value",
			source: `// %s:ignore:*[versioning.enabled=false]
resource "aws_s3_bucket" "test" {
  dynamic "versioning" {
    for_each = [{}]
    content {
      enabled = false
    }
  }
}`,
			assertLength: 0,
		},
		{
			name: "ignore by each.value",
			source: `locals {
  acls = toset(["private", "public"])
}

// %s:ignore:*[each.value=private]
resource "aws_s3_bucket" "test" {
  for_each = local.acls

  acl = each.value
}`,
			assertLength: 1,
		},
		{
			name: "ignore by nested each.value",
			source: `locals {
  acls = {
    private = {
      permission = "private"
    }
    public = {
      permission = "public"
    }
  }
}

// %s:ignore:*[each.value.permission=private]
resource "aws_s3_bucket" "test" {
  for_each = local.acls

  acl = each.value.permission
}`,
			assertLength: 1,
		},
		{
			name: "ignore resource with `count` meta-argument",
			source: `// %s:ignore:*[count.index=1]
resource "aws_s3_bucket" "test" {
  count = 2
}`,
			assertLength: 1,
		},
		{
			name: "invalid index when accessing blocks",
			source: `// %s:ignore:*[ingress.99.port=9090]
// %s:ignore:*[ingress.-10.port=9090]
resource "aws_s3_bucket" "test" {
  dynamic "ingress" {
    for_each = [8080, 9090]
    content {
      port = ingress.value
    }
  }
}`,
			assertLength: 1,
		},
		{
			name: "ignore by list value",
			source: `#%s:ignore:*[someattr.1.Environment=dev]
resource "aws_s3_bucket" "test" {
  someattr = [
	{
		Environment = "prod"
	},
	{
		Environment = "dev"
	}
  ]
}`,
			assertLength: 0,
		},
		{
			name: "ignore by list value with invalid index",
			source: `#%s:ignore:*[someattr.-2.Environment=dev]
resource "aws_s3_bucket" "test" {
  someattr = [
	{
		Environment = "prod"
	},
	{
		Environment = "dev"
	}
  ]
}`,
			assertLength: 1,
		},
		{
			name: "ignore by object value",
			source: `#%s:ignore:*[tags.Environment=dev]
resource "aws_s3_bucket" "test" {
  tags = {
    Environment = "dev"
  }
}`,
			assertLength: 0,
		},
		{
			name: "ignore by object value in block",
			source: `#%s:ignore:*[someblock.tags.Environment=dev]
resource "aws_s3_bucket" "test" {
  someblock {
	tags = {
	  Environment = "dev"
	}
  }
}`,
			assertLength: 0,
		},
		{
			name: "ignore by list value in map",
			source: `
variable "testvar" {
  type = map(list(string))
  default = {
    server1 = ["web", "dev"]
    server2 = ["prod"]
  }
}

#%s:ignore:*[someblock.someattr.server1.1=dev]
resource "aws_s3_bucket" "test" {
  someblock {
	someattr = var.testvar
  }
}
`,
			assertLength: 0,
		},
		{
			name: "ignore by alias",
			source: `#%s:ignore:my-alias
resource "aws_s3_bucket" "test" {}`,
			assertLength: 0,
		},
		{
			name: "ignore by alias with trivy prefix",
			source: `#%s:ignore:my-alias
resource "aws_s3_bucket" "test" {}`,
			assertLength: 0,
		},
		{
			name: "ignore for implied IAM resource",
			source: `# %s:ignore:aws-iam-enforce-mfa
resource "aws_iam_group" "this" {
  name = "group-name" 
}

resource "aws_iam_policy" "this" {
  name   = "test-policy"                                 
  policy = data.aws_iam_policy_document.this.json 
}


resource "aws_iam_group_policy_attachment" "this" {
  group      = aws_iam_group.this.name
  policy_arn = aws_iam_policy.this.arn                         
}

data "aws_iam_policy_document" "this" {
  statement {
    sid = "PublishToCloudWatch" 
    actions = [
      "cloudwatch:PutMetricData", 
    ]
    resources = ["*"]
  }
}`,
			assertLength: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			prefixes := []string{"tfsec", "trivy"}
			for _, prefix := range prefixes {
				t.Run(prefix, func(t *testing.T) {
					results := scanHCL(
						t, formatWithSingleValue(tc.source, prefix),
						rego.WithPolicyReader(
							strings.NewReader(emptyBucketCheck),
							strings.NewReader(enforceGroupMfaCheck)),
						rego.WithPolicyNamespaces("user"),
					)
					assert.Len(t, results.GetFailed(), tc.assertLength)
				})
			}
		})
	}
}

func formatWithSingleValue(format string, value any) string {
	count := strings.Count(format, "%s")

	args := make([]any, count)
	for i := range args {
		args[i] = value
	}

	return fmt.Sprintf(format, args...)
}

func Test_IgnoreByDynamicBlockValue(t *testing.T) {

	check := `# METADATA
# custom:
#   avd_id: USER-TEST-0124
#   short_code: test
#   provider: aws
#   service: ec2
package user.test124

import rego.v1

deny contains res if  {
	some group in input.aws.ec2.securitygroups
	some rule in group.ingressrules
	rule.toport.value < 1024
	res := result.new(
		sprintf("Port below 1024 is not allowed, but got %s", [rule.toport.value]),
		rule.toport,
	)
}
`

	tests := []struct {
		name     string
		source   string
		expected int
	}{
		{
			name: "by dynamic value",
			source: `// trivy:ignore:*[ingress.from_port=80]
resource "aws_security_group" "loadbalancer" {
  name = "test"

  dynamic "ingress" {
    for_each = [80, 443]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
`,
			expected: 0,
		},
		{
			name: "access by index",
			source: `// trivy:ignore:*[ingress.0.from_port=80]
resource "aws_security_group" "loadbalancer" {
  name = "test"

  dynamic "ingress" {
    for_each = [80, 443]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := scanHCL(t, tt.source,
				rego.WithPolicyReader(strings.NewReader(check)),
				rego.WithPolicyNamespaces("user"))
			require.Len(t, results.GetFailed(), tt.expected)
		})
	}
}

func Test_IgnoreByWorkspace(t *testing.T) {

	tests := []struct {
		name           string
		src            string
		expectedFailed int
	}{
		{
			name: "with expiry and workspace",
			src: `# tfsec:ignore:aws-s3-non-empty-bucket:exp:2221-01-02:ws:testworkspace
resource "aws_s3_bucket" "test" {}`,
			expectedFailed: 0,
		},
		{
			name: "bad workspace",
			src: `# tfsec:ignore:aws-s3-non-empty-bucket:exp:2221-01-02:ws:otherworkspace
resource "aws_s3_bucket" "test" {}`,
			expectedFailed: 1,
		},
		{
			name: "with expiry and workspace, trivy prefix",
			src: `# trivy:ignore:aws-s3-non-empty-bucket:exp:2221-01-02:ws:testworkspace
resource "aws_s3_bucket" "test" {}`,
			expectedFailed: 0,
		},
		{
			name: "bad workspace, trivy prefix",
			src: `# trivy:ignore:aws-s3-non-empty-bucket:exp:2221-01-02:ws:otherworkspace
resource "aws_s3_bucket" "test" {}`,
			expectedFailed: 1,
		},
		{
			name: "workspace with wildcard",
			src: `# tfsec:ignore:*:ws:test* 
resource "aws_s3_bucket" "test" {}`,
			expectedFailed: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := scanHCL(t, tt.src,
				rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
				rego.WithPolicyNamespaces("user"),
				ScannerWithWorkspaceName("testworkspace"),
			)
			assert.Len(t, results.GetFailed(), tt.expectedFailed)
		})
	}
}

func Test_IgnoreInlineByAVDID(t *testing.T) {
	testCases := []struct {
		input string
	}{
		{
			input: `resource "aws_s3_bucket" "test" {
  bucket = "" # tfsec:ignore:%s
}
	  `,
		},
		{
			input: `resource "aws_s3_bucket" "test" {
  bucket = "" # trivy:ignore:%s
}
	  `,
		},
	}

	for _, tc := range testCases {
		ids := []string{
			"USER-TEST-0123", strings.ToLower("user-test-0123"),
			"non-empty-bucket", "aws-s3-non-empty-bucket",
		}

		for _, id := range ids {
			t.Run(id, func(t *testing.T) {
				results := scanHCL(t, fmt.Sprintf(tc.input, id),
					rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
					rego.WithPolicyNamespaces("user"),
				)
				testutil.AssertRuleNotFailed(t, "aws-s3-non-empty-bucket", results, "")
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
# trivy:ignore:user-test-0123
resource "aws_s3_bucket" "test" {
  bucket = ""
}
`,
	})

	results, err := scanFS(fsys, ".",
		rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
		rego.WithPolicyNamespaces("user"),
	)
	require.NoError(t, err)
	testutil.AssertRuleNotFailed(t, "aws-s3-non-empty-bucket", results, "")
}
