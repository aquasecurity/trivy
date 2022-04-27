package keyvault

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPurge = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AZU-0016",
		Provider:   providers.AzureProvider,
		Service:    "keyvault",
		ShortCode:  "no-purge",
		Summary:    "Key vault should have purge protection enabled",
		Impact:     "Keys could be purged from the vault without protection",
		Resolution: "Enable purge protection for key vaults",
		Explanation: `Purge protection is an optional Key Vault behavior and is not enabled by default.

Purge protection can only be enabled once soft-delete is enabled. It can be turned on via CLI or PowerShell.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPurgeGoodExamples,
			BadExamples:         terraformNoPurgeBadExamples,
			Links:               terraformNoPurgeLinks,
			RemediationMarkdown: terraformNoPurgeRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, vault := range s.Azure.KeyVault.Vaults {
			if vault.IsUnmanaged() {
				continue
			}
			if vault.EnablePurgeProtection.IsFalse() {
				results.Add(
					"Vault does not have purge protection enabled.",
					vault.EnablePurgeProtection,
				)
			} else if vault.EnablePurgeProtection.IsTrue() && (vault.SoftDeleteRetentionDays.LessThan(7) || vault.SoftDeleteRetentionDays.GreaterThan(90)) {
				results.Add(
					"Resource should have soft_delete_retention_days set between 7 and 90 days in order to enable purge protection.",
					vault.SoftDeleteRetentionDays,
				)
			} else {
				results.AddPassed(&vault)
			}
		}
		return
	},
)
