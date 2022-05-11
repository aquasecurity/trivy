package sql

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/google/sql"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckPgLogErrors = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0018",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-errors",
		Summary:     "Ensure that Postgres errors are logged",
		Impact:      "Loss of error logging",
		Resolution:  "Set the minimum log severity to at least ERROR",
		Explanation: `Setting the minimum log severity too high will cause errors not to be logged`,
		Links: []string{
			"https://postgresqlco.nf/doc/en/param/log_min_messages/",
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-MESSAGES",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformPgLogErrorsGoodExamples,
			BadExamples:         terraformPgLogErrorsBadExamples,
			Links:               terraformPgLogErrorsLinks,
			RemediationMarkdown: terraformPgLogErrorsRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql.DatabaseFamilyPostgres {
				continue
			}
			if instance.Settings.Flags.LogMinMessages.IsOneOf("FATAL", "PANIC", "LOG") {
				results.Add(
					"Database instance is not configured to log errors.",
					instance.Settings.Flags.LogMinMessages,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
