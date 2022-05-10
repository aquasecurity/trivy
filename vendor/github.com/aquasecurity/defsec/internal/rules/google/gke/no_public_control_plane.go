package gke

import (
	"github.com/aquasecurity/defsec/internal/cidr"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicControlPlane = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0053",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "no-public-control-plane",
		Summary:     "GKE Control Plane should not be publicly accessible",
		Impact:      "GKE control plane exposed to public internet",
		Resolution:  "Use private nodes and master authorised networks to prevent exposure",
		Explanation: `The GKE control plane is exposed to the public internet by default.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicControlPlaneGoodExamples,
			BadExamples:         terraformNoPublicControlPlaneBadExamples,
			Links:               terraformNoPublicControlPlaneLinks,
			RemediationMarkdown: terraformNoPublicControlPlaneRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			for _, block := range cluster.MasterAuthorizedNetworks.CIDRs {
				if cidr.IsPublic(block.Value()) {
					results.Add(
						"Cluster exposes control plane to the public internet.",
						block,
					)
				} else {
					results.AddPassed(&cluster)
				}

			}
		}
		return
	},
)
