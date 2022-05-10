package elb

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var outdatedSSLPolicies = []string{
	"ELBSecurityPolicy-2015-05",
	"ELBSecurityPolicy-TLS-1-0-2015-04",
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
}

var CheckUseSecureTlsPolicy = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0047",
		Provider:    providers.AWSProvider,
		Service:     "elb",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "An outdated SSL policy is in use by a load balancer.",
		Impact:      "The SSL policy is outdated and has known vulnerabilities",
		Resolution:  "Use a more recent TLS/SSL policy for the load balancer",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, lb := range s.AWS.ELB.LoadBalancers {
			for _, listener := range lb.Listeners {
				for _, outdated := range outdatedSSLPolicies {
					if listener.TLSPolicy.EqualTo(outdated) {
						results.Add(
							"Listener uses an outdated TLS policy.",
							listener.TLSPolicy,
						)
					} else {
						results.AddPassed(&listener)
					}
				}
			}
		}
		return
	},
)
