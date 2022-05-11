package appservice

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckRequireClientCert = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0001",
		Provider:    providers.AzureProvider,
		Service:     "appservice",
		ShortCode:   "require-client-cert",
		Summary:     "Web App accepts incoming client certificate",
		Impact:      "Mutual TLS is not being used",
		Resolution:  "Enable incoming certificates for clients",
		Explanation: `The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled only an authenticated client with valid certificates can access the app.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRequireClientCertGoodExamples,
			BadExamples:         terraformRequireClientCertBadExamples,
			Links:               terraformRequireClientCertLinks,
			RemediationMarkdown: terraformRequireClientCertRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.IsUnmanaged() {
				continue
			}
			if service.EnableClientCert.IsFalse() {
				results.Add(
					"App service does not have client certificates enabled.",
					service.EnableClientCert,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
