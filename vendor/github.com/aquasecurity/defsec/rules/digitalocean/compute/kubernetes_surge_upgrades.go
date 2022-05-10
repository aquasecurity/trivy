package compute

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckKubernetesSurgeUpgrades = rules.Register(
	rules.Rule{
		AVDID:       "AVD-DIG-0005",
		Provider:    providers.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "surge-upgrades-not-enabled",
		Summary:     "The Kubernetes cluster does not enable surge upgrades",
		Impact:      "Upgrades may influence availability of your Kubernetes cluster",
		Resolution:  "Enable surge upgrades in your Kubernetes cluster",
		Explanation: `While upgrading your cluster, workloads will temporarily be moved to new nodes. A small cost will follow, but as a bonus, you won't experience downtime.`,
		Links: []string{
			"https://docs.digitalocean.com/products/kubernetes/how-to/upgrade-cluster/#surge-upgrades",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformKubernetesClusterSurgeUpgradesGoodExamples,
			BadExamples:         terraformKubernetesClusterSurgeUpgradesBadExamples,
			Links:               terraformKubernetesClusterSurgeUpgradeLinks,
			RemediationMarkdown: terraformKubernetesClusterSurgeUpgradesMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, kc := range s.DigitalOcean.Compute.KubernetesClusters {
			if kc.IsUnmanaged() {
				continue
			}
			if kc.SurgeUpgrade.IsFalse() {
				results.Add(
					"Surge upgrades are disabled in your Kubernetes cluster. Please enable this feature.",
					kc.SurgeUpgrade,
				)
			} else {
				results.AddPassed(&kc)
			}
		}
		return
	},
)
