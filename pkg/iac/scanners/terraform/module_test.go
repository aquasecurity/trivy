package terraform

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

var emptyBucketCheck = `# METADATA
# schemas:
# - input: schema.cloud
# custom:
#   avd_id: USER-TEST-0123
#   short_code: non-empty-bucket
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: s3
#           provider: aws
package user.test123

import rego.v1

deny contains res if  {
	some bucket in input.aws.s3.buckets
	bucket.name.value == ""
	res := result.new("The bucket name cannot be empty.", bucket)
}
`

// IMPORTANT: if this test is failing, you probably need to set the version of go-cty in go.mod to the same version that hcl uses.
func Test_GoCtyCompatibilityIssue(t *testing.T) {
	fsys := testutil.CreateFS(t, map[string]string{
		"/project/main.tf": `
data "aws_vpc" "default" {
  default = true
}

module "test" {
  source     = "../modules/problem/"
  cidr_block = data.aws_vpc.default.cidr_block
}
`,
		"/modules/problem/main.tf": `
variable "cidr_block" {}

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

resource "aws_s3_bucket" "test" {
  bucket = ""
}
`,
	})

	assertNonEmptyBucketCheckFound(t, fsys)
}

func Test_ProblemInModuleInSiblingDir(t *testing.T) {

	fsys := testutil.CreateFS(t, map[string]string{
		"/project/main.tf": `
module "something" {
	source = "../modules/problem"
}
`,
		"modules/problem/main.tf": `
resource "aws_s3_bucket" "test" {
  bucket = ""
}
`},
	)

	assertNonEmptyBucketCheckFound(t, fsys)

}

func Test_ProblemInModuleIgnored(t *testing.T) {

	fsys := testutil.CreateFS(t, map[string]string{
		"/project/main.tf": `
#tfsec:ignore:cloud-general-non-empty-bucket
module "something" {
	source = "../modules/problem"
}
`,
		"modules/problem/main.tf": `
resource "aws_s3_bucket" "test" {
  bucket = ""
}
`},
	)

	assertNonEmptyBucketCheckNotFound(t, fsys)
}

func Test_ProblemInModuleInSubdirectory(t *testing.T) {

	fsys := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
module "something" {
	source = "./modules/problem"
}
`,
		"project/modules/problem/main.tf": `
resource "aws_s3_bucket" "test" {
  bucket = ""
}
`})

	assertNonEmptyBucketCheckFound(t, fsys)
}

func Test_ProblemInModuleInParentDir(t *testing.T) {

	fsys := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
module "something" {
	source = "../problem"
}
`,
		"problem/main.tf": `
resource "aws_s3_bucket" "test" {
  bucket = ""
}
`})

	assertNonEmptyBucketCheckFound(t, fsys)
}

func Test_ProblemInModuleReuse(t *testing.T) {

	fsys := testutil.CreateFS(t, map[string]string{
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
`})

	assertNonEmptyBucketCheckFound(t, fsys)
}

func Test_ProblemInNestedModule(t *testing.T) {

	fsys := testutil.CreateFS(t, map[string]string{
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
		"modules/c/main.tf": `
resource "aws_s3_bucket" "test" {
  bucket = ""
}
`,
	})

	assertNonEmptyBucketCheckFound(t, fsys)
}

func Test_ProblemInReusedNestedModule(t *testing.T) {
	fsys := testutil.CreateFS(t, map[string]string{
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
	})

	assertNonEmptyBucketCheckFound(t, fsys)
}

func Test_ProblemInInitialisedModule(t *testing.T) {

	fsys := testutil.CreateFS(t, map[string]string{
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
}

`,
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
	})

	assertNonEmptyBucketCheckFound(t, fsys)
}

func Test_ProblemInReusedInitialisedModule(t *testing.T) {

	fsys := testutil.CreateFS(t, map[string]string{
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
	})

	assertNonEmptyBucketCheckFound(t, fsys)
}

func Test_ProblemInDuplicateModuleNameAndPath(t *testing.T) {
	fsys := testutil.CreateFS(t, map[string]string{
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
  bucket = ""
}
`,
	})

	assertNonEmptyBucketCheckFound(t, fsys)
}

func Test_Dynamic_Variables(t *testing.T) {
	fsys := testutil.CreateFS(t, map[string]string{
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
`})

	assertNonEmptyBucketCheckFound(t, fsys)
}

func Test_Dynamic_Variables_FalsePositive(t *testing.T) {
	fsys := testutil.CreateFS(t, map[string]string{
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
}
`})

	assertNonEmptyBucketCheckNotFound(t, fsys)
}

func Test_ReferencesPassedToNestedModule(t *testing.T) {

	fsys := testutil.CreateFS(t, map[string]string{
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
`})

	assertNonEmptyBucketCheckNotFound(t, fsys)

}

func scanFS(fsys fs.FS, target string) (scan.Results, error) {
	s := New(
		rego.WithEmbeddedLibraries(true),
		rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
		rego.WithPolicyNamespaces("user"),
		options.ScannerWithRegoOnly(true),
		ScannerWithAllDirectories(true),
	)

	return s.ScanFS(context.TODO(), fsys, target)
}

func assertNonEmptyBucketCheckFound(t *testing.T, fsys fs.FS) {
	t.Helper()

	results, err := scanFS(fsys, "project")
	require.NoError(t, err)

	testutil.AssertRuleFound(t, "cloud-general-non-empty-bucket", results, "")
}

func assertNonEmptyBucketCheckNotFound(t *testing.T, fsys fs.FS) {
	t.Helper()

	results, err := scanFS(fsys, "project")
	require.NoError(t, err)

	testutil.AssertRuleNotFound(t, "cloud-general-non-empty-bucket", results, "")
}
