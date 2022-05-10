package appservice

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnforceHttps = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0004",
		Provider:    providers.AzureProvider,
		Service:     "appservice",
		ShortCode:   "enforce-https",
		Summary:     "Ensure the Function App can only be accessed via HTTPS. The default is false.",
		Impact:      "Anyone can access the Function App using HTTP.",
		Resolution:  "You can redirect all HTTP requests to the HTTPS port.",
		Explanation: `By default, clients can connect to function endpoints by using both HTTP or HTTPS. You should redirect HTTP to HTTPs because HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https",
			"https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnforceHttpsGoodExamples,
			BadExamples:         terraformEnforceHttpsBadExamples,
			Links:               terraformEnforceHttpsLinks,
			RemediationMarkdown: terraformEnforceHttpsRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, functionApp := range s.Azure.AppService.FunctionApps {
			if functionApp.IsUnmanaged() {
				continue
			}
			if functionApp.HTTPSOnly.IsFalse() {
				results.Add(
					"Function app does not have HTTPS enforced.",
					functionApp.HTTPSOnly,
				)
			} else {
				results.AddPassed(&functionApp)
			}
		}
		return
	},
)
