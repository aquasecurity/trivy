package appservice

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckAuthenticationEnabled = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AZU-0003",
		Provider:    providers.AzureProvider,
		Service:     "appservice",
		ShortCode:   "authentication-enabled",
		Summary:     "App Service authentication is activated",
		Impact:      "Anonymous HTTP requests will be accepted",
		Resolution:  "Enable authentication to prevent anonymous request being accepted",
		Explanation: `Enabling authentication ensures that all communications in the application are authenticated. The auth_settings block needs to be filled out with the appropriate auth backend settings`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformAuthenticationEnabledGoodExamples,
			BadExamples:         terraformAuthenticationEnabledBadExamples,
			Links:               terraformAuthenticationEnabledLinks,
			RemediationMarkdown: terraformAuthenticationEnabledRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.IsUnmanaged() {
				continue
			}
			if service.Authentication.Enabled.IsFalse() {
				results.Add(
					"App service does not have authentication enabled.",
					service.Authentication.Enabled,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
