package storage

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/azure/storage"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0007",
		Provider:   providers.AzureProvider,
		Service:    "storage",
		ShortCode:  "no-public-access",
		Summary:    "Storage containers in blob storage mode should not have public access",
		Impact:     "Data in the storage container could be exposed publicly",
		Resolution: "Disable public access to storage containers",
		Explanation: `Storage container public access should be off. It can be configured for blobs only, containers and blobs or off entirely. The default is off, with no public access.

Explicitly overriding publicAccess to anything other than off should be avoided.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal#set-the-public-access-level-for-a-container",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, account := range s.Azure.Storage.Accounts {
			for _, container := range account.Containers {
				if container.PublicAccess.NotEqualTo(storage.PublicAccessOff) {
					results.Add(
						"Container allows public access.",
						container.PublicAccess,
					)
				} else {
					results.AddPassed(&container)
				}
			}
		}
		return
	},
)
