package sam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckApiUseSecureTlsPolicy = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0112",
		Provider:    providers.AWSProvider,
		Service:     "sam",
		ShortCode:   "api-use-secure-tls-policy",
		Summary:     "SAM API domain name uses outdated SSL/TLS protocols.",
		Impact:      "Outdated SSL policies increase exposure to known vulnerabilities",
		Resolution:  "Use the most modern TLS/SSL policies available",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-api-domainconfiguration.html#sam-api-domainconfiguration-securitypolicy",
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationApiUseSecureTlsPolicyGoodExamples,
			BadExamples:         cloudFormationApiUseSecureTlsPolicyBadExamples,
			Links:               cloudFormationApiUseSecureTlsPolicyLinks,
			RemediationMarkdown: cloudFormationApiUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, api := range s.AWS.SAM.APIs {
			if api.DomainConfiguration.SecurityPolicy.NotEqualTo("TLS_1_2") {
				results.Add(
					"Domain name is configured with an outdated TLS policy.",
					api.DomainConfiguration.SecurityPolicy,
				)
			} else {
				results.AddPassed(&api)
			}
		}
		return
	},
)
