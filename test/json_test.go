package test

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/rules"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/trivy-iac/test/testutil"
)

func TestScanningJSON(t *testing.T) {

	var tests = []struct {
		name       string
		source     string
		shouldFail bool
	}{
		{
			name: "check results are picked up in tf json configs",
			source: `
			{
				"provider": {
					"aws": {
						"profile": null,
						"region": "eu-west-1"
					}
				},
				"resource": {
					"bad": {
						"thing": {
							"type": "ingress",
							"cidr_blocks": ["0.0.0.0/0"],
							"description": "testing"
						}
					}
				}
			}`,
			shouldFail: true,
		},
		{
			name: "check attributes are checked in tf json configs",
			source: `
			{
				"provider": {
					"aws": {
						"profile": null,
						"region": "eu-west-1"
					}
				},
				"resource": {
					"bad": {
						"or_not": {
							"secure": true
						}
					}
				}
			}`,
			shouldFail: false,
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
							results.Add("something", resourceBlock)
							return
						},
					},
				},
			}
			reg := rules.Register(r1)
			defer rules.Deregister(reg)

			results := scanJSON(t, test.source)
			var include, exclude string
			if test.shouldFail {
				include = r1.LongID()
			} else {
				exclude = r1.LongID()
			}
			if include != "" {
				testutil.AssertRuleFound(t, include, results, "false negative found")
			}
			if exclude != "" {
				testutil.AssertRuleNotFound(t, exclude, results, "false positive found")
			}
		})
	}
}
