package network

import (
	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckDisableRdpFromInternet = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AZU-0048",
		Provider:   providers.AzureProvider,
		Service:    "network",
		ShortCode:  "disable-rdp-from-internet",
		Summary:    "RDP access should not be accessible from the Internet, should be blocked on port 3389",
		Impact:     "Anyone from the internet can potentially RDP onto an instance",
		Resolution: "Block RDP port from internet",
		Explanation: `RDP access can be configured on either the network security group or in the network security group rule.

RDP access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any). Consider using the Azure Bastion Service.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/bastion/tutorial-create-host-portal",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformDisableRdpFromInternetGoodExamples,
			BadExamples:         terraformDisableRdpFromInternetBadExamples,
			Links:               terraformDisableRdpFromInternetLinks,
			RemediationMarkdown: terraformDisableRdpFromInternetRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, group := range s.Azure.Network.SecurityGroups {
			var failed bool
			for _, rule := range group.Rules {
				if rule.Allow.IsFalse() || rule.Outbound.IsTrue() {
					continue
				}
				for _, ports := range rule.DestinationPorts {
					if ports.Includes(3389) {
						for _, ip := range rule.SourceAddresses {
							if cidr.IsPublic(ip.Value()) && cidr.CountAddresses(ip.Value()) > 1 {
								failed = true
								results.Add(
									"Security group rule allows ingress to RDP port from multiple public internet addresses.",
									ip,
								)
							}
						}
					}
				}
				if !failed {
					results.AddPassed(&group)
				}
			}
		}
		return
	},
)
