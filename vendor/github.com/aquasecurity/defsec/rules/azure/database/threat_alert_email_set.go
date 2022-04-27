package database

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckThreatAlertEmailSet = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AZU-0018",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "threat-alert-email-set",
		Summary:     "At least one email address is set for threat alerts",
		Impact:      "Nobody will be prompty alerted in the case of a threat being detected",
		Resolution:  "Provide at least one email address for threat alerts",
		Explanation: `SQL Server sends alerts for threat detection via email, if there are no email addresses set then mitigation will be delayed.`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformThreatAlertEmailSetGoodExamples,
			BadExamples:         terraformThreatAlertEmailSetBadExamples,
			Links:               terraformThreatAlertEmailSetLinks,
			RemediationMarkdown: terraformThreatAlertEmailSetRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			for _, policy := range server.SecurityAlertPolicies {
				if len(policy.EmailAddresses) == 0 {
					results.Add(
						"Security alert policy does not include any email addresses for notification.",
						&policy,
					)
				} else {
					results.AddPassed(&policy)
				}
			}
		}
		return
	},
)
