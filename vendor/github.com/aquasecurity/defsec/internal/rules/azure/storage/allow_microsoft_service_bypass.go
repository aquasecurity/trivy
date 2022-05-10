package storage

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckAllowMicrosoftServiceBypass = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0010",
		Provider:   providers.AzureProvider,
		Service:    "storage",
		ShortCode:  "allow-microsoft-service-bypass",
		Summary:    "Trusted Microsoft Services should have bypass access to Storage accounts",
		Impact:     "Trusted Microsoft Services won't be able to access storage account unless rules set to allow",
		Resolution: "Allow Trusted Microsoft Services to bypass",
		Explanation: `Some Microsoft services that interact with storage accounts operate from networks that can't be granted access through network rules. 

To help this type of service work as intended, allow the set of trusted Microsoft services to bypass the network rules`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security#trusted-microsoft-services",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAllowMicrosoftServiceBypassGoodExamples,
			BadExamples:         terraformAllowMicrosoftServiceBypassBadExamples,
			Links:               terraformAllowMicrosoftServiceBypassLinks,
			RemediationMarkdown: terraformAllowMicrosoftServiceBypassRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, account := range s.Azure.Storage.Accounts {
			for _, rule := range account.NetworkRules {
				var found bool
				for _, bypass := range rule.Bypass {
					if bypass.EqualTo("AzureServices") {
						found = true
					}
				}
				if !found {
					results.Add(
						"Network rules do not allow bypass for Microsoft Services.",
						&rule,
					)
				} else {
					results.AddPassed(&rule)
				}

			}
		}
		return
	},
)
