package compute

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnforceHttps = rules.Register(
	rules.Rule{
		AVDID:      "AVD-DIG-0002",
		Provider:   providers.DigitalOceanProvider,
		Service:    "compute",
		ShortCode:  "enforce-https",
		Summary:    "The load balancer forwarding rule is using an insecure protocol as an entrypoint",
		Impact:     "Your inbound traffic is not protected",
		Resolution: "Switch to HTTPS to benefit from TLS security features",
		Explanation: `Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.`,
		Links: []string{
			"https://docs.digitalocean.com/products/networking/load-balancers/",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnforceHttpsGoodExamples,
			BadExamples:         terraformEnforceHttpsBadExamples,
			Links:               terraformEnforceHttpsLinks,
			RemediationMarkdown: terraformEnforceHttpsRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, lb := range s.DigitalOcean.Compute.LoadBalancers {
			for _, rule := range lb.ForwardingRules {
				if rule.EntryProtocol.EqualTo("http") {
					results.Add(
						"Load balancer has aforwarding rule which uses HTTP instead of HTTPS.",
						rule.EntryProtocol,
					)
				} else {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
