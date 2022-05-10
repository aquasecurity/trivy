package keyvault

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnsureSecretExpiry = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0017",
		Provider:   providers.AzureProvider,
		Service:    "keyvault",
		ShortCode:  "ensure-secret-expiry",
		Summary:    "Key Vault Secret should have an expiration date set",
		Impact:     "Long life secrets increase the opportunity for compromise",
		Resolution: "Set an expiry for secrets",
		Explanation: `Expiration Date is an optional Key Vault Secret behavior and is not set by default.

Set when the resource will be become inactive.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnsureSecretExpiryGoodExamples,
			BadExamples:         terraformEnsureSecretExpiryBadExamples,
			Links:               terraformEnsureSecretExpiryLinks,
			RemediationMarkdown: terraformEnsureSecretExpiryRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, vault := range s.Azure.KeyVault.Vaults {
			for _, secret := range vault.Secrets {
				if secret.ExpiryDate.IsNever() {
					results.Add(
						"Secret should have an expiry date specified.",
						secret.ExpiryDate,
					)
				} else {
					results.AddPassed(&secret)
				}
			}
		}
		return
	},
)
