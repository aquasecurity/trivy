package gke

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnablePrivateCluster = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0059",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-private-cluster",
		Summary:     "Clusters should be set to private",
		Impact:      "Nodes may be exposed to the public internet",
		Resolution:  "Enable private cluster",
		Explanation: `Enabling private nodes on a cluster ensures the nodes are only available internally as they will only be assigned internal addresses.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnablePrivateClusterGoodExamples,
			BadExamples:         terraformEnablePrivateClusterBadExamples,
			Links:               terraformEnablePrivateClusterLinks,
			RemediationMarkdown: terraformEnablePrivateClusterRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
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
