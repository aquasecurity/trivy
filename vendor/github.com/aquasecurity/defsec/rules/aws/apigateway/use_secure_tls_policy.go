package apigateway

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0005",
		Provider:    providers.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "API Gateway domain name uses outdated SSL/TLS protocols.",
		Impact:      "Outdated SSL policies increase exposure to known vulnerabilities",
		Resolution:  "Use the most modern TLS/SSL policies available",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links: []string{
			"https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, domain := range s.AWS.APIGateway.DomainNames {
			if domain.SecurityPolicy.NotEqualTo("TLS_1_2") {
				results.Add(
					"Domain name is configured with an outdated TLS policy.",
					domain.SecurityPolicy,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
