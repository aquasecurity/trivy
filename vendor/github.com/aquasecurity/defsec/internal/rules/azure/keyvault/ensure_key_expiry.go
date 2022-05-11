package keyvault

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnsureKeyExpiry = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0014",
		Provider:   providers.AzureProvider,
		Service:    "keyvault",
		ShortCode:  "ensure-key-expiry",
		Summary:    "Ensure that the expiration date is set on all keys",
		Impact:     "Long life keys increase the attack surface when compromised",
		Resolution: "Set an expiration date on the vault key",
		Explanation: `Expiration Date is an optional Key Vault Key behavior and is not set by default.

Set when the resource will be become inactive.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/powershell/module/az.keyvault/update-azkeyvaultkey?view=azps-5.8.0#example-1--modify-a-key-to-enable-it--and-set-the-expiration-date-and-tags",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnsureKeyExpiryGoodExamples,
			BadExamples:         terraformEnsureKeyExpiryBadExamples,
			Links:               terraformEnsureKeyExpiryLinks,
			RemediationMarkdown: terraformEnsureKeyExpiryRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, vault := range s.Azure.KeyVault.Vaults {
			for _, key := range vault.Keys {
				if key.ExpiryDate.IsNever() {
					results.Add(
						"Key should have an expiry date specified.",
						key.ExpiryDate,
					)
				} else {
					results.AddPassed(&key)
				}
			}
		}
		return
	},
)
