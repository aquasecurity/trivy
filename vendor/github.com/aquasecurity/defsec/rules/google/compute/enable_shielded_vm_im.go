package compute

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableShieldedVMIntegrityMonitoring = rules.Register(
	rules.Rule{
		AVDID:       "AVD-GCP-0045",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "enable-shielded-vm-im",
		Summary:     "Instances should have Shielded VM integrity monitoring enabled",
		Impact:      "No visibility of VM instance boot state.",
		Resolution:  "Enable Shielded VM Integrity Monitoring",
		Explanation: `Integrity monitoring helps you understand and make decisions about the state of your VM instances.`,
		Links: []string{
			"https://cloud.google.com/security/shielded-cloud/shielded-vm#integrity-monitoring",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableShieldedVmImGoodExamples,
			BadExamples:         terraformEnableShieldedVmImBadExamples,
			Links:               terraformEnableShieldedVmImLinks,
			RemediationMarkdown: terraformEnableShieldedVmImRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.ShieldedVM.IntegrityMonitoringEnabled.IsFalse() {
				results.Add(
					"Instance does not have shielded VM integrity monitoring enabled.",
					instance.ShieldedVM.IntegrityMonitoringEnabled,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
