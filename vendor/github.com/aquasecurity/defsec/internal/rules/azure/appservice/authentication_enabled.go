package appservice

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckAuthenticationEnabled = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0003",
		Provider:    providers.AzureProvider,
		Service:     "appservice",
		ShortCode:   "authentication-enabled",
		Summary:     "App Service authentication is activated",
		Impact:      "Anonymous HTTP requests will be accepted",
		Resolution:  "Enable authentication to prevent anonymous request being accepted",
		Explanation: `Enabling authentication ensures that all communications in the application are authenticated. The auth_settings block needs to be filled out with the appropriate auth backend settings`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAuthenticationEnabledGoodExamples,
			BadExamples:         terraformAuthenticationEnabledBadExamples,
			Links:               terraformAuthenticationEnabledLinks,
			RemediationMarkdown: terraformAuthenticationEnabledRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
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
