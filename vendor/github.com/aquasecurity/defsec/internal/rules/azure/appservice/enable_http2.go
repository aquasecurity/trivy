package appservice

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableHttp2 = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0005",
		Provider:    providers.AzureProvider,
		Service:     "appservice",
		ShortCode:   "enable-http2",
		Summary:     "Web App uses the latest HTTP version",
		Impact:      "Outdated versions of HTTP has security vulnerabilities",
		Resolution:  "Use the latest version of HTTP",
		Explanation: `Use the latest version of HTTP to ensure you are benefiting from security fixes`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableHttp2GoodExamples,
			BadExamples:         terraformEnableHttp2BadExamples,
			Links:               terraformEnableHttp2Links,
			RemediationMarkdown: terraformEnableHttp2RemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.IsUnmanaged() {
				continue
			}
			if service.Site.EnableHTTP2.IsFalse() {
				results.Add(
					"App service does not have HTTP/2 enabled.",
					service.Site.EnableHTTP2,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
