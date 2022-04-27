package appservice

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AZU-0006",
		Provider:    providers.AzureProvider,
		Service:     "appservice",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "Web App uses latest TLS version",
		Impact:      "The minimum TLS version for apps should be TLS1_2",
		Resolution:  "The TLS version being outdated and has known vulnerabilities",
		Explanation: `Use a more recent TLS/SSL policy for the App Service`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.IsUnmanaged() {
				continue
			}
			if service.Site.MinimumTLSVersion.NotEqualTo("1.2") {
				results.Add(
					"App service does not require a secure TLS version.",
					service.Site.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
