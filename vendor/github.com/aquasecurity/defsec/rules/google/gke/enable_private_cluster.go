package gke

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnablePrivateCluster = rules.Register(
	rules.Rule{
		AVDID:       "AVD-GCP-0059",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-private-cluster",
		Summary:     "Clusters should be set to private",
		Impact:      "Nodes may be exposed to the public internet",
		Resolution:  "Enable private cluster",
		Explanation: `Enabling private nodes on a cluster ensures the nodes are only available internally as they will only be assigned internal addresses.`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnablePrivateClusterGoodExamples,
			BadExamples:         terraformEnablePrivateClusterBadExamples,
			Links:               terraformEnablePrivateClusterLinks,
			RemediationMarkdown: terraformEnablePrivateClusterRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.PrivateCluster.EnablePrivateNodes.IsFalse() {
				results.Add(
					"Cluster does not have private nodes.",
					cluster.PrivateCluster.EnablePrivateNodes,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
