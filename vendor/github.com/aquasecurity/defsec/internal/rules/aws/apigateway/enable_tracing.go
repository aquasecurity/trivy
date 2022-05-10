package apigateway

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/apigateway"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableTracing = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0003",
		Provider:    providers.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "enable-tracing",
		Summary:     "API Gateway must have X-Ray tracing enabled",
		Impact:      "Without full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableTracingGoodExamples,
			BadExamples:         terraformEnableTracingBadExamples,
			Links:               terraformEnableTracingLinks,
			RemediationMarkdown: terraformEnableTracingRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, api := range s.AWS.APIGateway.APIs {
			if api.IsUnmanaged() {
				continue
			}
			if api.ProtocolType.NotEqualTo(apigateway.ProtocolTypeREST) {
				continue
			}
			for _, stage := range api.Stages {
				if stage.IsUnmanaged() || stage.Version.NotEqualTo(1) {
					continue
				}
				if stage.XRayTracingEnabled.IsFalse() {
					results.Add(
						"X-Ray tracing is not enabled,",
						stage.XRayTracingEnabled,
					)
				} else {
					results.AddPassed(&stage)
				}
			}
		}
		return
	},
)
