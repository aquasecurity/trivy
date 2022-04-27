package database

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableSslEnforcement = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AZU-0020",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "enable-ssl-enforcement",
		Summary:     "SSL should be enforced on database connections where applicable",
		Impact:      "Insecure connections could lead to data loss and other vulnerabilities",
		Resolution:  "Enable SSL enforcement",
		Explanation: `SSL connections should be enforced were available to ensure secure transfer and reduce the risk of compromising data in flight.`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableSslEnforcementGoodExamples,
			BadExamples:         terraformEnableSslEnforcementBadExamples,
			Links:               terraformEnableSslEnforcementLinks,
			RemediationMarkdown: terraformEnableSslEnforcementRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, server := range s.Azure.Database.MariaDBServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.MySQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		return
	},
)
