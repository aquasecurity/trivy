package ssm

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

var AvoidLeaksViaHTTP = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0134",
		Provider:    providers.AWSProvider,
		Service:     "ssm",
		ShortCode:   "avoid-leaks-via-http",
		Summary:     "Secrets should not be exfiltrated using Terraform HTTP data blocks",
		Impact:      "Secrets could be exposed outside of the organisation.",
		Resolution:  "Remove this potential exfiltration HTTP request.",
		Explanation: `The data.http block can be used to send secret data outside of the organisation.`,
		Links: []string{
			"https://sprocketfox.io/xssfox/2022/02/09/terraformsupply/",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformAvoidLeaksViaHTTPGoodExamples,
			BadExamples:         terraformAvoidLeaksViaHTTPBadExamples,
			Links:               terraformAvoidLeaksViaHTTPLinks,
			RemediationMarkdown: terraformAvoidLeaksViaHTTPRemediationMarkdown,
		},
		CustomChecks: rules.CustomChecks{
			Terraform: &rules.TerraformCustomCheck{
				RequiredTypes:  []string{"data"},
				RequiredLabels: []string{"http"},
				Check: func(block *terraform.Block, module *terraform.Module) (results rules.Results) {
					attr := block.GetAttribute("url")
					if attr.IsNil() {
						return
					}
					for _, ref := range attr.AllReferences() {
						if ref.BlockType().Name() == "resource" && ref.TypeLabel() == "aws_ssm_parameter" {
							results.Add("Potential exfiltration of secret value detected", block)
						}
					}
					return
				},
			},
		},
		Severity: severity.Critical,
	},
	nil,
)
