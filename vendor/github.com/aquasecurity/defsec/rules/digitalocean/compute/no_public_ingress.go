package compute

import (
	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicIngress = rules.Register(
	rules.Rule{
		AVDID:       "AVD-DIG-0001",
		Provider:    providers.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "no-public-ingress",
		Summary:     "The firewall has an inbound rule with open access",
		Impact:      "Your port is exposed to the internet",
		Resolution:  "Set a more restrictive CIRDR range",
		Explanation: `Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.`,
		Links: []string{
			"https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressGoodExamples,
			BadExamples:         terraformNoPublicIngressBadExamples,
			Links:               terraformNoPublicIngressLinks,
			RemediationMarkdown: terraformNoPublicIngressRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, firewall := range s.DigitalOcean.Compute.Firewalls {
			var failed bool
			for _, rule := range firewall.InboundRules {
				for _, address := range rule.SourceAddresses {
					if cidr.IsPublic(address.Value()) && cidr.CountAddresses(address.Value()) > 1 {
						failed = true
						results.Add(
							"Ingress rule allows access from multiple public addresses.",
							address,
						)
					}
				}
			}
			if !failed {
				results.AddPassed(&firewall)
			}
		}
		return
	},
)
