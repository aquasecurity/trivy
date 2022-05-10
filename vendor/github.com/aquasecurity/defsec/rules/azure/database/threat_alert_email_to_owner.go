package database

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckThreatAlertEmailToOwner = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AZU-0023",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "threat-alert-email-to-owner",
		Summary:     "Security threat alerts go to subcription owners and co-administrators",
		Impact:      "Administrators and subscription owners may have a delayed response",
		Resolution:  "Enable email to subscription owners",
		Explanation: `Subscription owners should be notified when there are security alerts. By ensuring the administrators of the account have been notified they can quickly assist in any required remediation`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformThreatAlertEmailToOwnerGoodExamples,
			BadExamples:         terraformThreatAlertEmailToOwnerBadExamples,
			Links:               terraformThreatAlertEmailToOwnerLinks,
			RemediationMarkdown: terraformThreatAlertEmailToOwnerRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			for _, policy := range server.SecurityAlertPolicies {
				if policy.EmailAccountAdmins.IsFalse() {
					results.Add(
						"Security alert policy does not alert account admins.",
						policy.EmailAccountAdmins,
					)
				} else {
					results.AddPassed(&policy)
				}
			}
		}
		return
	},
)
