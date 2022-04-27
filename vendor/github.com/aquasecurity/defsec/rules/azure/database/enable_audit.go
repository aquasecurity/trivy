package database

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableAudit = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AZU-0027",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "enable-audit",
		Summary:     "Auditing should be enabled on Azure SQL Databases",
		Impact:      "Auditing provides valuable information about access and usage",
		Resolution:  "Enable auditing on Azure SQL databases",
		Explanation: `Auditing helps you maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableAuditGoodExamples,
			BadExamples:         terraformEnableAuditBadExamples,
			Links:               terraformEnableAuditLinks,
			RemediationMarkdown: terraformEnableAuditRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			if len(server.ExtendedAuditingPolicies) == 0 && server.IsManaged() {
				results.Add(
					"Server does not have an extended audit policy configured.",
					&server,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		return
	},
)
