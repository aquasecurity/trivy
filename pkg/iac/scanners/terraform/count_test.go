package terraform

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
)

func Test_ResourcesWithCount(t *testing.T) {
	var tests = []struct {
		name     string
		source   string
		expected int
	}{
		{
			name: "unspecified count defaults to 1",
			source: `
			resource "aws_s3_bucket" "test" {}
`,
			expected: 1,
		},
		{
			name: "count is literal 1",
			source: `
			resource "aws_s3_bucket" "test" {
				count = 1
			}
`,
			expected: 1,
		},
		{
			name: "count is literal 99",
			source: `
			resource "aws_s3_bucket" "test" {
				count = 99
			}
`,
			expected: 99,
		},
		{
			name: "count is literal 0",
			source: `
			resource "aws_s3_bucket" "test" {
				count = 0
			}
`,
			expected: 0,
		},
		{
			name: "count is 0 from variable",
			source: `
			variable "count" {
				default = 0
			}
			resource "aws_s3_bucket" "test" {
				count = var.count
			}
`,
			expected: 0,
		},
		{
			name: "count is 1 from variable",
			source: `
			variable "count" {
				default = 1
			}
			resource "aws_s3_bucket" "test" {
				count =  var.count
			}
`,
			expected: 1,
		},
		{
			name: "count is 1 from variable without default",
			source: `
			variable "count" {
			}
			resource "aws_s3_bucket" "test" {
				count =  var.count
			}
`,
			expected: 1,
		},
		{
			name: "count is 0 from conditional",
			source: `
			variable "enabled" {
				default = false
			}
			resource "aws_s3_bucket" "test" {
				count = var.enabled ? 1 : 0
			}
`,
			expected: 0,
		},
		{
			name: "count is 1 from conditional",
			source: `
			variable "enabled" {
				default = true
			}
			resource "aws_s3_bucket" "test" {
				count = var.enabled ? 1 : 0
			}
`,
			expected: 1,
		},
		{
			name: "issue 962",
			source: `
			resource "something" "else" {
				count = 2
				ok = true
			}

			resource "aws_s3_bucket" "test" {
				bucket = something.else[0].ok ? "test" : ""
			}	
`,
			expected: 0,
		},
		{
			name: "Test use of count.index",
			source: `
resource "aws_s3_bucket" "test" {
	count = 1
	bucket = var.things[count.index]["ok"] ? "test" : ""
}
	
variable "things" {
	description = "A list of maps that creates a number of sg"
	type = list(map(string))
	
	default = [
		{
			ok = true
		}
	]
}
			`,
			expected: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(t, test.source,
				rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
				rego.WithPolicyNamespaces("user"),
			)

			assert.Len(t, results.GetFailed(), test.expected)

			if test.expected > 0 {
				testutil.AssertRuleFound(t, "aws-s3-non-empty-bucket", results, "false negative found")
			} else {
				testutil.AssertRuleNotFound(t, "aws-s3-non-empty-bucket", results, "false positive found")
			}
		})
	}
}
