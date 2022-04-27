package compute

import (
	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicEgress = rules.Register(
	rules.Rule{
		AVDID:      "AVD-GCP-0035",
		Provider:   providers.GoogleProvider,
		Service:    "compute",
		ShortCode:  "no-public-egress",
		Summary:    "An outbound firewall rule allows traffic to /0.",
		Impact:     "The port is exposed for egress to the internet",
		Resolution: "Set a more restrictive cidr range",
		Explanation: `Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.`,
		Links: []string{
			"https://cloud.google.com/vpc/docs/using-firewalls",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPublicEgressGoodExamples,
			BadExamples:         terraformNoPublicEgressBadExamples,
			Links:               terraformNoPublicEgressLinks,
			RemediationMarkdown: terraformNoPublicEgressRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, network := range s.Google.Compute.Networks {
			if network.Firewall == nil {
				continue
			}
			for _, rule := range network.Firewall.EgressRules {
				if !rule.IsAllow.IsTrue() {
					continue
				}
				if rule.Enforced.IsFalse() {
					continue
				}
				for _, destination := range rule.DestinationRanges {
					if cidr.IsPublic(destination.Value()) && cidr.CountAddresses(destination.Value()) > 1 {
						results.Add(
							"Firewall rule allows egress traffic to multiple addresses on the public internet.",
							destination,
						)
					} else {
						results.AddPassed(destination)
					}
				}
			}
		}
		return
	},
)
