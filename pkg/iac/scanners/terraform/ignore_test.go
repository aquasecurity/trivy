package terraform

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

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
			name: "inline rule",
			source: `
resource "aws_s3_bucket" "test" {
  bucket = "" // tfsec:ignore:*
}
`,
			assertLength: 0,
		},
		{
			name: "rule above block",
			source: `
// tfsec:ignore:*
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "rule above block with boolean parameter",
			source: `
// tfsec:ignore:*[object_lock_enabled=false]
resource "aws_s3_bucket" "test" {
  object_lock_enabled = false
}
`,
			assertLength: 0,
		},
		{
			name: "rule above block with non-matching boolean parameter",
			source: `
// tfsec:ignore:*[object_lock_enabled=false]
resource "aws_s3_bucket" "test" {
  object_lock_enabled = true
}
`,
			assertLength: 1,
		},
		{
			name: "rule above block with string parameter",
			source: `
// tfsec:ignore:*[acl=private]
resource "aws_s3_bucket" "test" {
    acl = "private"
}
`,
			assertLength: 0,
		},
		{
			name: "rule above block with non-matching string parameter",
			source: `
// tfsec:ignore:*[acl=private]
resource "aws_s3_bucket" "test" {
    acl = "public"
}
`,
			assertLength: 1,
		},
		{
			name: "rule above block with int parameter",
			source: `
// tfsec:ignore:*[some_int=123]
resource "aws_s3_bucket" "test" {
   some_int = 123
}
`,
			assertLength: 0,
		},
		{
			name: "rule above block with non-matching int parameter",
			source: `
// tfsec:ignore:*[some_int=456]
resource "aws_s3_bucket" "test" {
   some_int = 123
}
`,
			assertLength: 1,
		},
		{
			name: "stacked rules above block",
			source: `
// tfsec:ignore:*
// tfsec:ignore:a
// tfsec:ignore:b
// tfsec:ignore:c
// tfsec:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "stacked rules above block without a match",
			source: `
#tfsec:ignore:*

#tfsec:ignore:x
#tfsec:ignore:a
#tfsec:ignore:b
#tfsec:ignore:c
#tfsec:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 1,
		},
		{
			name: "stacked rules above block without spaces between '#' comments",
			source: `
#tfsec:ignore:*
#tfsec:ignore:a
#tfsec:ignore:b
#tfsec:ignore:c
#tfsec:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "stacked rules above block without spaces between '//' comments",
			source: `
//tfsec:ignore:*
//tfsec:ignore:a
//tfsec:ignore:b
//tfsec:ignore:c
//tfsec:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "rule above the finding",
			source: `
resource "aws_s3_bucket" "test" {
	# tfsec:ignore:aws-s3-non-empty-bucket
    bucket = ""
}
`,
			assertLength: 0,
		},
		{
			name: "rule with breached expiration date",
			source: `
resource "aws_s3_bucket" "test" {
    bucket = "" # tfsec:ignore:aws-s3-non-empty-bucket:exp:2000-01-02
}
`,
			assertLength: 1,
		},
		{
			name: "rule with unbreached expiration date",
			source: `
resource "aws_s3_bucket" "test" {
    bucket = "" # tfsec:ignore:aws-s3-non-empty-bucket:exp:2221-01-02
}
`,
			assertLength: 0,
		},
		{
			name: "rule with invalid expiration date",
			source: `
resource "aws_s3_bucket" "test" {
   bucket = "" # tfsec:ignore:aws-s3-non-empty-bucket:exp:2221-13-02
}
`,
			assertLength: 1,
		},
		{
			name: "rule above block with unbreached expiration date",
			source: `
#tfsec:ignore:aws-s3-non-empty-bucket:exp:2221-01-02
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "trivy inline rule ignore all checks",
			source: `
resource "aws_s3_bucket" "test" {
    bucket = "" // trivy:ignore:*
}
`,
			assertLength: 0,
		},
		{
			name: "trivy rule above the block",
			source: `
// trivy:ignore:*
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "trivy rule above block with boolean parameter",
			source: `
// trivy:ignore:*[force_destroy=true]
resource "aws_s3_bucket" "test" {
  force_destroy = true
}
`,
			assertLength: 0,
		},
		{
			name: "trivy rule above block with non-matching boolean parameter",
			source: `
// trivy:ignore:*[force_destroy=false]
resource "aws_s3_bucket" "test" {
  force_destroy = true
}
`,
			assertLength: 1,
		},
		{
			name: "trivy rule above block with string parameter",
			source: `
// trivy:ignore:*[acl=private]
resource "aws_s3_bucket" "test" {
    acl = "private"
}
`,
			assertLength: 0,
		},
		{
			name: "trivy rule above block with non-matching string parameter",
			source: `
// trivy:ignore:*[acl=private]
resource "aws_s3_bucket" "test" {
    acl = "public" 
}
`,
			assertLength: 1,
		},
		{
			name: "trivy rule above block with int parameter",
			source: `
// trivy:ignore:*[some_int=123]
resource "aws_s3_bucket" "test" {
   some_int = 123
}
`,
			assertLength: 0,
		},
		{
			name: "trivy rule above block with non-matching int parameter",
			source: `
// trivy:ignore:*[some_int=456]
resource "aws_s3_bucket" "test" {
   some_int = 123
}
`,
			assertLength: 1,
		},
		{
			name: "ignore by nested attribute",
			source: `
// trivy:ignore:*[versioning.enabled=false]
resource "aws_s3_bucket" "test" {
  versioning {
    enabled = false
  }
}
`,
			assertLength: 0,
		},
		{
			name: "ignore by nested attribute of another type",
			source: `
// trivy:ignore:*[versioning.enabled=1]
resource "aws_s3_bucket" "test" {
  versioning {
    enabled = false
  }
}
`,
			assertLength: 1,
		},
		{
			name: "ignore by non-existent nested attribute",
			source: `
// trivy:ignore:*[versioning.target=foo]
resource "aws_s3_bucket" "test" {
  versioning {
    enabled = false
  }
}
`,
			assertLength: 1,
		},
		{
			name: "ignore resource with `for_each` meta-argument",
			source: `
// trivy:ignore:*[acl=public]
resource "aws_s3_bucket" "test" {
  for_each = toset(["private", "public"])
  acl = each.value
}
`,
			assertLength: 1,
		},
		{
			name: "ignore by dynamic block value",
			source: `
// trivy:ignore:*[versioning.enabled=false]
resource "aws_s3_bucket" "test" {
  dynamic "versioning" {
    for_each = [{}]
    content {
      enabled = false
    }
  }
}
`,
			assertLength: 0,
		},
		{
			name: "trivy rules stacked above the block",
			source: `
// trivy:ignore:*
// trivy:ignore:a
// trivy:ignore:b
// trivy:ignore:c
// trivy:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "Trivy rules stacked above the block without a match",
			source: `
#trivy:ignore:*

#trivy:ignore:x
#trivy:ignore:a
#trivy:ignore:b
#trivy:ignore:c
#trivy:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 1,
		},
		{
			name: "trivy rules stacked above the block with hashes and no spaces",
			source: `
#trivy:ignore:*
#trivy:ignore:a
#trivy:ignore:b
#trivy:ignore:c
#trivy:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "trivy rules stacked above the block without spaces",
			source: `
//trivy:ignore:*
//trivy:ignore:a
//trivy:ignore:b
//trivy:ignore:c
//trivy:ignore:d
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "trivy rule above the finding",
			source: `
resource "aws_s3_bucket" "test" {
	# trivy:ignore:aws-s3-non-empty-bucket
    bucket = ""
}
`,
			assertLength: 0,
		},
		{
			name: "trivy rule with breached expiration date",
			source: `
resource "aws_s3_bucket" "test" {
    bucket = "" # trivy:ignore:aws-s3-non-empty-bucket:exp:2000-01-02
}
`,
			assertLength: 1,
		},
		{
			name: "trivy rule with unbreached expiration date",
			source: `
resource "aws_s3_bucket" "test" {
    bucket = "" # trivy:ignore:aws-s3-non-empty-bucket:exp:2221-01-02
}
`,
			assertLength: 0,
		},
		{
			name: "trivy rule with invalid expiration date",
			source: `
resource "aws_s3_bucket" "test" {
   bucket = "" # trivy:ignore:aws-s3-non-empty-bucket:exp:2221-13-02
}
`,
			assertLength: 1,
		},
		{
			name: "trivy rule above block with unbreached expiration date",
			source: `
#trivy:ignore:aws-s3-non-empty-bucket:exp:2221-01-02
resource "aws_s3_bucket" "test" {}
`,
			assertLength: 0,
		},
		{
			name: "ignore by each.value",
			source: `
// trivy:ignore:*[each.value=false]
resource "bad" "my-rule" {
  for_each = toset(["false", "true", "false"])

  secure   = each.value
}
`,
			assertLength: 0,
		},
		{
			name: "ignore by nested each.value",
			source: `
locals {
  acls = toset(["private", "public"])
}
// trivy:ignore:*[each.value=private]
resource "aws_s3_bucket" "test" {
  for_each = local.acls

  acl = each.value
}
`,
			assertLength: 1,
		},
		{
			name: "ignore resource with `count` meta-argument",
			source: `
// trivy:ignore:*[count.index=1]
resource "aws_s3_bucket" "test" {
  count = 2
}
`,
			assertLength: 1,
		},
		{
			name: "invalid index when accessing blocks",
			source: `
// trivy:ignore:*[ingress.99.port=9090]
// trivy:ignore:*[ingress.-10.port=9090]
resource "aws_s3_bucket" "test" {
  dynamic "ingress" {
    for_each = [8080, 9090]
    content {
      port = ingress.value
    }
  }
}
`,
			assertLength: 1,
		},
		{
			name: "ignore by list value",
			source: `
#trivy:ignore:*[someattr.1.Environment=dev]
resource "aws_s3_bucket" "test" {
  someattr = [
	{
		Environment = "prod"
	},
	{
		Environment = "dev"
	}
  ]
}
`,
			assertLength: 0,
		},
		{
			name: "ignore by list value with invalid index",
			source: `
#trivy:ignore:*[someattr.-2.Environment=dev]
resource "aws_s3_bucket" "test" {
  secure = false
  someattr = [
	{
		Environment = "prod"
	},
	{
		Environment = "dev"
	}
  ]
}
`,
			assertLength: 1,
		},
		{
			name: "ignore by object value",
			source: `
#trivy:ignore:*[tags.Environment=dev]
resource "aws_s3_bucket" "test" {
  secure = false
  tags = {
    Environment = "dev"
  }
}
`,
			assertLength: 0,
		},
		{
			name: "ignore by object value in block",
			source: `
#trivy:ignore:*[someblock.tags.Environment=dev]
resource "aws_s3_bucket" "test" {
  secure = false
  someblock {
	tags = {
	  Environment = "dev"
	}
  }
}
`,
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

#trivy:ignore:*[someblock.someattr.server1.1=dev]
resource "aws_s3_bucket" "test" {
  secure = false
  someblock {
	someattr = var.testvar
  }
}
`,
			assertLength: 0,
		},
		{
			name: "ignore by alias",
			source: `#tfsec:ignore:my-alias
resource "aws_s3_bucket" "test" {}`,
			assertLength: 0,
		},
		{
			name: "ignore by alias with trivy prefix",
			source: `#tfsec:ignore:my-alias
resource "aws_s3_bucket" "test" {}`,
			assertLength: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := scanHCL(
				t, tc.source,
				rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
				rego.WithPolicyNamespaces("user"),
			)
			assert.Len(t, results.GetFailed(), tc.assertLength)
		})
	}
}

func Test_IgnoreByIndexedDynamicBlock(t *testing.T) {

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
			fsys := fstest.MapFS{
				"main.tf": {
					Data: []byte(tt.source),
				},
			}

			results, err := scanFS(fsys, ".",
				rego.WithPolicyReader(strings.NewReader(check)),
				rego.WithPolicyNamespaces("user"))
			require.NoError(t, err)
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
			fsys := fstest.MapFS{
				"main.tf": &fstest.MapFile{
					Data: []byte(tt.src),
				},
			}

			results, err := scanFS(fsys, ".",
				rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
				rego.WithPolicyNamespaces("user"),
				ScannerWithWorkspaceName("testworkspace"),
			)
			require.NoError(t, err)
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
				fsys := fstest.MapFS{
					"main.tf": &fstest.MapFile{
						Data: []byte(fmt.Sprintf(tc.input, id)),
					},
				}
				assertNonEmptyBucketCheckNotFound(t, fsys)
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

	assertNonEmptyBucketCheckNotFound(t, fsys)
}
