package apigateway

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableAccessLogging = rules.Register(
	rules.Rule{
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
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableAccessLoggingGoodExamples,
			BadExamples:         terraformEnableAccessLoggingBadExamples,
			Links:               terraformEnableAccessLoggingLinks,
			RemediationMarkdown: terraformEnableAccessLoggingRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableAccessLoggingGoodExamples,
			BadExamples:         cloudFormationEnableAccessLoggingBadExamples,
			Links:               cloudFormationEnableAccessLoggingLinks,
			RemediationMarkdown: cloudFormationEnableAccessLoggingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
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
