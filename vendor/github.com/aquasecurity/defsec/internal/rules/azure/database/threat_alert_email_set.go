package database

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckThreatAlertEmailSet = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0018",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "threat-alert-email-set",
		Summary:     "At least one email address is set for threat alerts",
		Impact:      "Nobody will be prompty alerted in the case of a threat being detected",
		Resolution:  "Provide at least one email address for threat alerts",
		Explanation: `SQL Server sends alerts for threat detection via email, if there are no email addresses set then mitigation will be delayed.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformThreatAlertEmailSetGoodExamples,
			BadExamples:         terraformThreatAlertEmailSetBadExamples,
			Links:               terraformThreatAlertEmailSetLinks,
			RemediationMarkdown: terraformThreatAlertEmailSetRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
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
