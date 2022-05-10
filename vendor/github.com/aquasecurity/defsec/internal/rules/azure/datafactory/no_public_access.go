package datafactory

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0035",
		Provider:   providers.AzureProvider,
		Service:    "datafactory",
		ShortCode:  "no-public-access",
		Summary:    "Data Factory should have public access disabled, the default is enabled.",
		Impact:     "Data factory is publicly accessible",
		Resolution: "Set public access to disabled for Data Factory",
		Explanation: `Data Factory has public access set to true by default.

Disabling public network access is applicable only to the self-hosted integration runtime, not to Azure Integration Runtime and SQL Server Integration Services (SSIS) Integration Runtime.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations#hybrid-scenarios",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, factory := range s.Azure.DataFactory.DataFactories {
			if factory.EnablePublicNetwork.IsTrue() {
				results.Add(
					"Data factory allows public network access.",
					factory.EnablePublicNetwork,
				)
			} else {
				results.AddPassed(&factory)
			}
		}
		return
	},
)
