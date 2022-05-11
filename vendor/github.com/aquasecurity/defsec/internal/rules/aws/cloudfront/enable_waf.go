package cloudfront

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableWaf = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0011",
		Provider:    providers.AWSProvider,
		Service:     "cloudfront",
		ShortCode:   "enable-waf",
		Summary:     "CloudFront distribution does not have a WAF in front.",
		Impact:      "Complex web application attacks can more easily be performed without a WAF",
		Resolution:  "Enable WAF for the CloudFront distribution",
		Explanation: `You should configure a Web Application Firewall in front of your CloudFront distribution. This will mitigate many types of attacks on your web application.`,
		Links: []string{
			"https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableWafGoodExamples,
			BadExamples:         terraformEnableWafBadExamples,
			Links:               terraformEnableWafLinks,
			RemediationMarkdown: terraformEnableWafRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableWafGoodExamples,
			BadExamples:         cloudFormationEnableWafBadExamples,
			Links:               cloudFormationEnableWafLinks,
			RemediationMarkdown: cloudFormationEnableWafRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, dist := range s.AWS.Cloudfront.Distributions {
			if dist.WAFID.IsEmpty() {
				results.Add(
					"Distribution does not utilise a WAF.",
					dist.WAFID,
				)
			} else {
				results.AddPassed(&dist)
			}
		}
		return
	},
)
