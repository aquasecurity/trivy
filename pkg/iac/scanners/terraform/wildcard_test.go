package terraform

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Test_WildcardMatchingOnRequiredLabels(t *testing.T) {

	tests := []struct {
		input           string
		pattern         string
		expectedFailure bool
	}{
		{
			pattern:         "aws_*",
			input:           `resource "aws_instance" "blah" {}`,
			expectedFailure: true,
		},
		{
			pattern:         "gcp_*",
			input:           `resource "aws_instance" "blah" {}`,
			expectedFailure: false,
		},
		{
			pattern:         "x_aws_*",
			input:           `resource "aws_instance" "blah" {}`,
			expectedFailure: false,
		},
		{
			pattern:         "aws_security_group*",
			input:           `resource "aws_security_group" "blah" {}`,
			expectedFailure: true,
		},
		{
			pattern:         "aws_security_group*",
			input:           `resource "aws_security_group_rule" "blah" {}`,
			expectedFailure: true,
		},
	}

	for i, test := range tests {

		code := fmt.Sprintf("wild%d", i)

		t.Run(code, func(t *testing.T) {

			rule := scan.Rule{
				Service:   "service",
				ShortCode: code,
				Summary:   "blah",
				Provider:  "custom",
				Severity:  severity.High,
				CustomChecks: scan.CustomChecks{
					Terraform: &scan.TerraformCustomCheck{
						RequiredTypes:  []string{"resource"},
						RequiredLabels: []string{test.pattern},
						Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results scan.Results) {
							results.Add("Custom check failed for resource.", resourceBlock)
							return
						},
					},
				},
			}
			reg := rules.Register(rule)
			defer rules.Deregister(reg)

			results := scanHCL(t, test.input)

			if test.expectedFailure {
				testutil.AssertRuleFound(t, fmt.Sprintf("custom-service-%s", code), results, "")
			} else {
				testutil.AssertRuleNotFound(t, fmt.Sprintf("custom-service-%s", code), results, "")
			}
		})
	}

}
