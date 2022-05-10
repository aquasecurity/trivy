package sql

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/providers/google/sql"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckPgNoMinStatementLogging = rules.Register(
	rules.Rule{
		AVDID:       "AVD-GCP-0021",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-no-min-statement-logging",
		Summary:     "Ensure that logging of long statements is disabled.",
		Impact:      "Sensitive data could be exposed in the database logs.",
		Resolution:  "Disable minimum duration statement logging completely",
		Explanation: `Logging of statements which could contain sensitive data is not advised, therefore this setting should preclude all statements from being logged.`,
		Links: []string{
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-DURATION-STATEMENT",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformPgNoMinStatementLoggingGoodExamples,
			BadExamples:         terraformPgNoMinStatementLoggingBadExamples,
			Links:               terraformPgNoMinStatementLoggingLinks,
			RemediationMarkdown: terraformPgNoMinStatementLoggingRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql.DatabaseFamilyPostgres {
				continue
			}
			if instance.Settings.Flags.LogMinDurationStatement.NotEqualTo(-1) {
				results.Add(
					"Database instance is configured to log statements.",
					instance.Settings.Flags.LogMinDurationStatement,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
