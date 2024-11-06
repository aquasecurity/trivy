package terraform

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
)

func Test_Modules(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		expected bool
	}{
		{
			// IMPORTANT: if this test is failing, you probably need to set the version of go-cty in go.mod to the same version that hcl uses.
			name: "go-cty compatibility issue",
			files: map[string]string{
				"/project/main.tf": `
data "aws_vpc" "default" {
  default = true
}

module "test" {
  source     = "../modules/problem/"
  cidr_block = data.aws_vpc.default.cidr_block
}`,
				"/modules/problem/main.tf": `variable "cidr_block" {}

variable "open" {                
  default = false
}                

resource "aws_security_group" "this" {
  name = "Test"                       

  ingress {    
    description = "HTTPs"
    from_port   = 443    
    to_port     = 443
    protocol    = "tcp"
    self        = ! var.open
    cidr_blocks = var.open ? [var.cidr_block] : null
  }                                                 
}  

resource "aws_s3_bucket" "test" {}`,
			},
			expected: true,
		},
		{
			name: "misconfig in sibling directory module",
			files: map[string]string{
				"/project/main.tf": `
module "something" {
	source = "../modules/problem"
}
`,
				"modules/problem/main.tf": `
resource "aws_s3_bucket" "test" {}`,
			},
			expected: true,
		},
		{
			name: "ignore misconfig in module",
			files: map[string]string{
				"/project/main.tf": `
#tfsec:ignore:aws-s3-non-empty-bucket
module "something" {
	source = "../modules/problem"
}
`,
				"modules/problem/main.tf": `
resource "aws_s3_bucket" "test" {}
`,
			},
			expected: false,
		},
		{
			name: "misconfig in subdirectory module",
			files: map[string]string{
				"project/main.tf": `
module "something" {
	source = "./modules/problem"
}
`,
				"project/modules/problem/main.tf": `
resource "aws_s3_bucket" "test" {}
`,
			},
			expected: true,
		},
		{
			name: "misconfig in parent directory module",
			files: map[string]string{
				"project/main.tf": `
module "something" {
	source = "../problem"
}
`,
				"problem/main.tf": `
resource "aws_s3_bucket" "test" {}
`},
			expected: true,
		},
		{
			name: "misconfig in reused module",
			files: map[string]string{
				"project/main.tf": `
module "something_good" {
	source = "../modules/problem"
	bucket = "test"
}

module "something_bad" {
	source = "../modules/problem"
	bucket = ""
}
`,
				"modules/problem/main.tf": `
variable "bucket" {}

resource "aws_s3_bucket" "test" {
  bucket = var.bucket
}
`},
			expected: true,
		},
		{
			name: "misconfig in nested module",
			files: map[string]string{
				"project/main.tf": `
module "something" {
	source = "../modules/a"
}
`,
				"modules/a/main.tf": `
	module "something" {
	source = "../../modules/b"
}
`,
				"modules/b/main.tf": `
module "something" {
	source = "../c"
}
`,
				"modules/c/main.tf": `resource "aws_s3_bucket" "test" {}`,
			},
			expected: true,
		},
		{
			name: "misconfig in reused nested module",
			files: map[string]string{
				"project/main.tf": `
module "something" {
  source = "../modules/a"
  bucket = "test"
}

module "something-bad" {
	source = "../modules/a"
	bucket = ""
}
`,
				"modules/a/main.tf": `
variable "bucket" {}

module "something" {
	source = "../../modules/b"
	bucket = var.bucket
}
`,
				"modules/b/main.tf": `
variable "bucket" {}

module "something" {
	source = "../c"
	bucket = var.bad
}
`,
				"modules/c/main.tf": `
variable "bucket" {}

resource "aws_s3_bucket" "test" {
  bucket = var.bucket
}
`,
			},
			expected: true,
		},
		{
			name: "misconfig in terraform cached module",
			files: map[string]string{
				"project/main.tf": `
module "something" {
  	source = "../modules/somewhere"
	bucket = "test"
}
`,
				"modules/somewhere/main.tf": `
module "something_nested" {
	count = 1
  	source = "github.com/some/module.git"
	bucket = ""
}

variable "bucket" {
	default = ""
}`,
				"project/.terraform/modules/something.something_nested/main.tf": `
variable "bucket" {}

resource "aws_s3_bucket" "test" {
  bucket = var.bucket
}
`,
				"project/.terraform/modules/modules.json": `
	{"Modules":[
        {"Key":"something","Source":"../modules/somewhere","Version":"2.35.0","Dir":"../modules/somewhere"},
        {"Key":"something.something_nested","Source":"git::https://github.com/some/module.git","Version":"2.35.0","Dir":".terraform/modules/something.something_nested"}
    ]}
`,
			},
			expected: true,
		},
		{
			name: "misconfig in reused terraform cached module",
			files: map[string]string{
				"project/main.tf": `
module "something" {
  	source = "/nowhere"
	bucket = ""
} 

module "something2" {
	source = "/nowhere"
  	bucket = ""
}
`,
				"project/.terraform/modules/a/main.tf": `
variable "bucket" {}

resource "aws_s3_bucket" "test" {
  bucket = var.bucket
}
`,
				"project/.terraform/modules/modules.json": `
	{"Modules":[{"Key":"something","Source":"/nowhere","Version":"2.35.0","Dir":".terraform/modules/a"},{"Key":"something2","Source":"/nowhere","Version":"2.35.0","Dir":".terraform/modules/a"}]}
`,
			},
			expected: true,
		},
		{
			name: "misconfig in nested modules with duplicate module names and paths",
			files: map[string]string{
				"project/main.tf": `
module "something" {
  source = "../modules/a"
  s3_bucket_count = 0
}

module "something-bad" {
	source = "../modules/a"
	s3_bucket_count = 1
}
`,
				"modules/a/main.tf": `
variable "s3_bucket_count" {
	default = 0
}
module "something" {
	source = "../b"
	s3_bucket_count = var.s3_bucket_count
}
`,
				"modules/b/main.tf": `
variable "s3_bucket_count" {
	default = 0
}
module "something" {
	source = "../c"
	s3_bucket_count = var.s3_bucket_count
}
`,
				"modules/c/main.tf": `
variable "s3_bucket_count" {
	default = 0
}

resource "aws_s3_bucket" "test" {
  count = var.s3_bucket_count
}
`,
			},
			expected: true,
		},
		{
			name: "misconfigured attribute referencing to dynamic variable",
			files: map[string]string{
				"project/main.tf": `
resource "something" "this" {
	dynamic "blah" {
		for_each = ["a"]
		content {
			bucket = ""
		}
	}
}

resource "aws_s3_bucket" "test" {
  secure = something.this.blah[0].bucket
}
`},
			expected: true,
		},
		{
			name: "attribute referencing to dynamic variable without index",
			files: map[string]string{
				"project/main.tf": `
resource "something" "else" {
	dynamic "blah" {
		for_each = toset(["test"])
		content {
			bucket = blah.value
		}
	}
}

resource "aws_s3_bucket" "test" {
  bucket = something.else.blah.bucket
}`},
			expected: false,
		},
		{
			name: "references passed to nested module",
			files: map[string]string{
				"project/main.tf": `

resource "some_resource" "this" {
    name = "test"
}

module "something" {
	source = "../modules/a"
    bucket = some_resource.this.name
}
`,
				"modules/a/main.tf": `
variable "bucket" {
    type = string
}

resource "aws_s3_bucket" "test" {
  bucket = var.bucket
}
`},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := testutil.CreateFS(t, tt.files)
			results, err := scanFS(fsys, "project",
				rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
				rego.WithPolicyNamespaces("user"),
			)
			require.NoError(t, err)
			if tt.expected {
				testutil.AssertRuleFound(t, "aws-s3-non-empty-bucket", results, "")
			} else {
				testutil.AssertRuleNotFailed(t, "aws-s3-non-empty-bucket", results, "")
			}
		})
	}
}
