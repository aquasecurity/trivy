package apigateway

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableAccessLogging = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0001",
		Provider:    providers.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "enable-access-logging",
		Summary:     "API Gateway stages for V1 and V2 should have access logging enabled",
		Impact:      "Logging provides vital information about access and usage",
		Resolution:  "Enable logging for API Gateway stages",
		Explanation: `API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.`,
		Links: []string{
			"https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableAccessLoggingGoodExamples,
			BadExamples:         terraformEnableAccessLoggingBadExamples,
			Links:               terraformEnableAccessLoggingLinks,
			RemediationMarkdown: terraformEnableAccessLoggingRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableAccessLoggingGoodExamples,
			BadExamples:         cloudFormationEnableAccessLoggingBadExamples,
			Links:               cloudFormationEnableAccessLoggingLinks,
			RemediationMarkdown: cloudFormationEnableAccessLoggingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, api := range s.AWS.APIGateway.APIs {
			for _, stage := range api.Stages {
				if stage.IsUnmanaged() {
					continue
				}
				if stage.AccessLogging.CloudwatchLogGroupARN.IsEmpty() {
					results.Add(
						"Access logging is not configured.",
						stage.AccessLogging.CloudwatchLogGroupARN,
					)
				} else {
					results.AddPassed(&api)
				}
			}
		}
		return
	},
)
