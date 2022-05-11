package compute

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckAutoUpgrade = rules.Register(
	scan.Rule{
		AVDID:       "AVD-DIG-0008",
		Provider:    providers.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "kubernetes-auto-upgrades-not-enabled",
		Summary:     "Kubernetes clusters should be auto-upgraded to ensure that they always contain the latest security patches.",
		Impact:      "Not running the latest security patches on your Kubernetes cluster can make it a target for penetration.",
		Resolution:  "Set maintenance policy deterministically when auto upgrades are enabled",
		Explanation: ``,
		Links: []string{
			"https://docs.digitalocean.com/products/kubernetes/resources/best-practices/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformKubernetesClusterAutoUpgradeGoodExample,
			BadExamples:         terraformKubernetesClusterAutoUpgradeBadExample,
			Links:               terraformKubernetesClusterAutoUpgradeLinks,
			RemediationMarkdown: terraformKubernetesAutoUpgradeMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, kc := range s.DigitalOcean.Compute.KubernetesClusters {
			if kc.IsUnmanaged() {
				continue
			}
			if kc.AutoUpgrade.IsFalse() {
				results.Add(
					"Kubernetes Cluster does not enable auto upgrades enabled",
					kc.AutoUpgrade,
				)
			} else {
				results.AddPassed(&kc)
			}
		}
		return
	},
)
