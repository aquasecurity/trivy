package sql

import (
	"github.com/aquasecurity/defsec/internal/cidr"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0017",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "no-public-access",
		Summary:     "Ensure that Cloud SQL Database Instances are not publicly exposed",
		Impact:      "Public exposure of sensitive data",
		Resolution:  "Remove public access from database instances",
		Explanation: `Database instances should be configured so that they are not available over the public internet, but to internal compute resources which access them.`,
		Links: []string{
			"https://www.cloudconformity.com/knowledge-base/gcp/CloudSQL/publicly-accessible-cloud-sql-instances.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.Settings.IPConfiguration.EnableIPv4.IsTrue() {
				results.Add(
					"Database instance is granted a public internet address.",
					instance.Settings.IPConfiguration.EnableIPv4,
				)
			}
			for _, network := range instance.Settings.IPConfiguration.AuthorizedNetworks {
				if cidr.IsPublic(network.CIDR.Value()) {
					results.Add(
						"Database instance allows access from the public internet.",
						network.CIDR,
					)
				} else {
					results.AddPassed(&instance)
				}
			}
		}
		return
	},
)
