package network

import (
	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicEgress = rules.Register(
	rules.Rule{
		AVDID:       "AVD-KUBE-0002",
		Provider:    providers.KubernetesProvider,
		Service:     "network",
		ShortCode:   "no-public-egress",
		Summary:     "Public egress should not be allowed via network policies",
		Impact:      "Exfiltration of data to the public internet",
		Resolution:  "Remove public access except where explicitly required",
		Explanation: `You should not expose infrastructure to the public internet except where explicitly required`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPublicEgressGoodExamples,
			BadExamples:         terraformNoPublicEgressBadExamples,
			Links:               terraformNoPublicEgressLinks,
			RemediationMarkdown: terraformNoPublicEgressRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, policy := range s.Kubernetes.NetworkPolicies {
			if policy.IsUnmanaged() {
				continue
			}
			for _, destination := range policy.Spec.Egress.DestinationCIDRs {
				if cidr.IsPublic(destination.Value()) {
					results.Add(
						"Network policy allows egress to the public internet.",
						destination,
					)
				} else {
					results.AddPassed(destination)
				}
			}
		}
		return
	},
)
