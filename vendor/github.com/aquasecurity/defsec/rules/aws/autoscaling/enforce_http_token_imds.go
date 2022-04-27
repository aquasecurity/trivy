package autoscaling

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckIMDSAccessRequiresToken = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0130",
		Provider:   providers.AWSProvider,
		Service:    "autoscaling",
		ShortCode:  "enforce-http-token-imds",
		Summary:    "aws_instance should activate session tokens for Instance Metadata Service.",
		Impact:     "Instance metadata service can be interacted with freely",
		Resolution: "Enable HTTP token requirement for IMDS",
		Explanation: `
IMDS v2 (Instance Metadata Service) introduced session authentication tokens which improve security when talking to IMDS.
By default <code>aws_instance</code> resource sets IMDS session auth tokens to be optional. 
To fully protect IMDS you need to enable session tokens by using <code>metadata_options</code> block and its <code>http_tokens</code> variable set to <code>required</code>.
`,

		Links: []string{
			"https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service",
		},

		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnforceHttpTokenImdsGoodExamples,
			BadExamples:         terraformEnforceHttpTokenImdsBadExamples,
			Links:               terraformEnforceHttpTokenImdsLinks,
			RemediationMarkdown: terraformEnforceHttpTokenImdsRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudformationEnforceHttpTokenImdsGoodExamples,
			BadExamples:         cloudformationEnforceHttpTokenImdsBadExamples,
			Links:               cloudformationEnforceHttpTokenImdsLinks,
			RemediationMarkdown: cloudformationEnforceHttpTokenImdsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, configuration := range s.AWS.Autoscaling.LaunchConfigurations {
			if !configuration.RequiresIMDSToken() && !configuration.HasHTTPEndpointDisabled() {
				results.Add(
					"Launch configuration does not require IMDS access to require a token",
					configuration.MetadataOptions.HttpTokens,
				)
			} else {
				results.AddPassed(&configuration)
			}
		}
		for _, instance := range s.AWS.Autoscaling.LaunchTemplates {
			if !instance.RequiresIMDSToken() && !instance.HasHTTPEndpointDisabled() {
				results.Add(
					"Launch template does not require IMDS access to require a token",
					instance.MetadataOptions.HttpTokens,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return results
	},
)
