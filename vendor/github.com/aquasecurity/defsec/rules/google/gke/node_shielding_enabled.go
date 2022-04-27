package gke

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNodeShieldingEnabled = rules.Register(
	rules.Rule{
		AVDID:      "AVD-GCP-0055",
		Provider:   providers.GoogleProvider,
		Service:    "gke",
		ShortCode:  "node-shielding-enabled",
		Summary:    "Shielded GKE nodes not enabled.",
		Impact:     "Node identity and integrity can't be verified without shielded GKE nodes",
		Resolution: "Enable node shielding",
		Explanation: `CIS GKE Benchmark Recommendation: 6.5.5. Ensure Shielded GKE Nodes are Enabled

Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNodeShieldingEnabledGoodExamples,
			BadExamples:         terraformNodeShieldingEnabledBadExamples,
			Links:               terraformNodeShieldingEnabledLinks,
			RemediationMarkdown: terraformNodeShieldingEnabledRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.EnableShieldedNodes.IsFalse() {
				results.Add(
					"Cluster has shielded nodes disabled.",
					cluster.EnableShieldedNodes,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
