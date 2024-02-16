package terraform

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/stretchr/testify/assert"
)

func Test_ResourcesWithCount(t *testing.T) {
	var tests = []struct {
		name            string
		source          string
		expectedResults int
	}{
		{
			name: "unspecified count defaults to 1",
			source: `
			resource "bad" "this" {}
`,
			expectedResults: 1,
		},
		{
			name: "count is literal 1",
			source: `
			resource "bad" "this" {
				count = 1
			}
`,
			expectedResults: 1,
		},
		{
			name: "count is literal 99",
			source: `
			resource "bad" "this" {
				count = 99
			}
`,
			expectedResults: 99,
		},
		{
			name: "count is literal 0",
			source: `
			resource "bad" "this" {
				count = 0
			}
`,
			expectedResults: 0,
		},
		{
			name: "count is 0 from variable",
			source: `
			variable "count" {
				default = 0
			}
			resource "bad" "this" {
				count = var.count
			}
`,
			expectedResults: 0,
		},
		{
			name: "count is 1 from variable",
			source: `
			variable "count" {
				default = 1
			}
			resource "bad" "this" {
				count =  var.count
			}
`,
			expectedResults: 1,
		},
		{
			name: "count is 1 from variable without default",
			source: `
			variable "count" {
			}
			resource "bad" "this" {
				count =  var.count
			}
`,
			expectedResults: 1,
		},
		{
			name: "count is 0 from conditional",
			source: `
			variable "enabled" {
				default = false
			}
			resource "bad" "this" {
				count = var.enabled ? 1 : 0
			}
`,
			expectedResults: 0,
		},
		{
			name: "count is 1 from conditional",
			source: `
			variable "enabled" {
				default = true
			}
			resource "bad" "this" {
				count = var.enabled ? 1 : 0
			}
`,
			expectedResults: 1,
		},
		{
			name: "issue 962",
			source: `
			resource "something" "else" {
				count = 2
				ok = true
			}

			resource "bad" "bad" {
				secure = something.else[0].ok
			}	
`,
			expectedResults: 0,
		},
		{
			name: "Test use of count.index",
			source: `
resource "bad" "thing" {
	count = 1
	secure = var.things[count.index]["ok"]
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
			expectedResults: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r1 := scan.Rule{
				Provider:  providers.AWSProvider,
				Service:   "service",
				ShortCode: "abc123",
				Severity:  severity.High,
				CustomChecks: scan.CustomChecks{
					Terraform: &scan.TerraformCustomCheck{
						RequiredLabels: []string{"bad"},
						Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results scan.Results) {
							if resourceBlock.GetAttribute("secure").IsTrue() {
								return
							}
							results.Add(
								"example problem",
								resourceBlock,
							)
							return
						},
					},
				},
			}
			reg := rules.Register(r1)
			defer rules.Deregister(reg)
			results := scanHCL(t, test.source)
			var include string
			var exclude string
			if test.expectedResults > 0 {
				include = r1.LongID()
			} else {
				exclude = r1.LongID()
			}
			assert.Equal(t, test.expectedResults, len(results.GetFailed()))
			if include != "" {
				testutil.AssertRuleFound(t, include, results, "false negative found")
			}
			if exclude != "" {
				testutil.AssertRuleNotFound(t, exclude, results, "false positive found")
			}
		})
	}
}
