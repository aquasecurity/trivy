package storage

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckQueueServicesLoggingEnabled = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0009",
		Provider:   providers.AzureProvider,
		Service:    "storage",
		ShortCode:  "queue-services-logging-enabled",
		Summary:    "When using Queue Services for a storage account, logging should be enabled.",
		Impact:     "Logging provides valuable information about access and usage",
		Resolution: "Enable logging for Queue Services",
		Explanation: `Storage Analytics logs detailed information about successful and failed requests to a storage service. 

This information can be used to monitor individual requests and to diagnose issues with a storage service. 

Requests are logged on a best-effort basis.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/storage/common/storage-analytics-logging?tabs=dotnet",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformQueueServicesLoggingEnabledGoodExamples,
			BadExamples:         terraformQueueServicesLoggingEnabledBadExamples,
			Links:               terraformQueueServicesLoggingEnabledLinks,
			RemediationMarkdown: terraformQueueServicesLoggingEnabledRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, account := range s.Azure.Storage.Accounts {
			if account.IsUnmanaged() {
				continue
			}
			if account.QueueProperties.EnableLogging.IsFalse() {
				results.Add(
					"Queue services storage account does not have logging enabled.",
					account.QueueProperties.EnableLogging,
				)
			} else {
				results.AddPassed(&account)
			}
		}
		return
	},
)
