package sql

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEncryptInTransitData = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0015",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "encrypt-in-transit-data",
		Summary:     "SSL connections to a SQL database instance should be enforced.",
		Impact:      "Intercepted data can be read in transit",
		Resolution:  "Enforce SSL for all connections",
		Explanation: `In-transit data should be encrypted so that if traffic is intercepted data will not be exposed in plaintext to attackers.`,
		Links: []string{
			"https://cloud.google.com/sql/docs/mysql/configure-ssl-instance",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEncryptInTransitDataGoodExamples,
			BadExamples:         terraformEncryptInTransitDataBadExamples,
			Links:               terraformEncryptInTransitDataLinks,
			RemediationMarkdown: terraformEncryptInTransitDataRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.Settings.IPConfiguration.RequireTLS.IsFalse() {
				results.Add(
					"Database instance does not require TLS for all connections.",
					instance.Settings.IPConfiguration.RequireTLS,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
