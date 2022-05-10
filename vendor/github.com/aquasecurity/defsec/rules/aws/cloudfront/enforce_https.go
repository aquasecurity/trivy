package cloudfront

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnforceHttps = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0012",
		Provider:   providers.AWSProvider,
		Service:    "cloudfront",
		ShortCode:  "enforce-https",
		Summary:    "CloudFront distribution allows unencrypted (HTTP) communications.",
		Impact:     "CloudFront is available through an unencrypted connection",
		Resolution: "Only allow HTTPS for CloudFront distribution communication",
		Explanation: `Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-s3-origin.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnforceHttpsGoodExamples,
			BadExamples:         terraformEnforceHttpsBadExamples,
			Links:               terraformEnforceHttpsLinks,
			RemediationMarkdown: terraformEnforceHttpsRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnforceHttpsGoodExamples,
			BadExamples:         cloudFormationEnforceHttpsBadExamples,
			Links:               cloudFormationEnforceHttpsLinks,
			RemediationMarkdown: cloudFormationEnforceHttpsRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, dist := range s.AWS.Cloudfront.Distributions {
			if dist.DefaultCacheBehaviour.ViewerProtocolPolicy.EqualTo(cloudfront.ViewerPolicyProtocolAllowAll) {
				results.Add(
					"Distribution allows unencrypted communications.",
					dist.DefaultCacheBehaviour.ViewerProtocolPolicy,
				)
			} else {
				results.AddPassed(&dist)
			}
			for _, behaviour := range dist.OrdererCacheBehaviours {
				if behaviour.ViewerProtocolPolicy.EqualTo(cloudfront.ViewerPolicyProtocolAllowAll) {
					results.Add(
						"Distribution allows unencrypted communications.",
						behaviour.ViewerProtocolPolicy,
					)
				} else {
					results.AddPassed(&behaviour)
				}
			}

		}
		return
	},
)
