package sam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableApiTracing = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0111",
		Provider:    providers.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-api-tracing",
		Summary:     "SAM API must have X-Ray tracing enabled",
		Impact:      "Without full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html#sam-api-tracingenabled",
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableApiTracingGoodExamples,
			BadExamples:         cloudFormationEnableApiTracingBadExamples,
			Links:               cloudFormationEnableApiTracingLinks,
			RemediationMarkdown: cloudFormationEnableApiTracingRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, api := range s.AWS.SAM.APIs {
			if api.IsUnmanaged() {
				continue
			}

			if api.TracingEnabled.IsFalse() {
				results.Add(
					"X-Ray tracing is not enabled,",
					api.TracingEnabled,
				)
			} else {
				results.AddPassed(&api)
			}
		}
		return
	},
)
