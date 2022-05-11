package sql

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/google/sql"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckPgLogDisconnections = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0022",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-disconnections",
		Summary:     "Ensure that logging of disconnections is enabled.",
		Impact:      "Insufficient diagnostic data.",
		Resolution:  "Enable disconnection logging.",
		Explanation: `Logging disconnections provides useful diagnostic data such as session length, which can identify performance issues in an application and potential DoS vectors.`,
		Links: []string{
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-DISCONNECTIONS",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformPgLogDisconnectionsGoodExamples,
			BadExamples:         terraformPgLogDisconnectionsBadExamples,
			Links:               terraformPgLogDisconnectionsLinks,
			RemediationMarkdown: terraformPgLogDisconnectionsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql.DatabaseFamilyPostgres {
				continue
			}
			if instance.Settings.Flags.LogDisconnections.IsFalse() {
				results.Add(
					"Database instance is not configured to log disconnections.",
					instance.Settings.Flags.LogDisconnections,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
