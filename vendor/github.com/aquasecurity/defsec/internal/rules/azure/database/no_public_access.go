package database

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0022",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "no-public-access",
		Summary:     "Ensure databases are not publicly accessible",
		Impact:      "Publicly accessible database could lead to compromised data",
		Resolution:  "Disable public access to database when not required",
		Explanation: `Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, server := range s.Azure.Database.MariaDBServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.EnablePublicNetworkAccess.IsTrue() {
				results.Add(
					"Database server has public network access enabled.",
					server.EnablePublicNetworkAccess,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.MSSQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.EnablePublicNetworkAccess.IsTrue() {
				results.Add(
					"Database server has public network access enabled.",
					server.EnablePublicNetworkAccess,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.MySQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.EnablePublicNetworkAccess.IsTrue() {
				results.Add(
					"Database server has public network access enabled.",
					server.EnablePublicNetworkAccess,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.EnablePublicNetworkAccess.IsTrue() {
				results.Add(
					"Database server has public network access enabled.",
					server.EnablePublicNetworkAccess,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		return
	},
)
