package sam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableHttpApiAccessLogging = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0116",
		Provider:    providers.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-http-api-access-logging",
		Summary:     "SAM HTTP API stages for V1 and V2 should have access logging enabled",
		Impact:      "Logging provides vital information about access and usage",
		Resolution:  "Enable logging for API Gateway stages",
		Explanation: `API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-httpapi.html#sam-httpapi-accesslogsettings",
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableHttpApiAccessLoggingGoodExamples,
			BadExamples:         cloudFormationEnableHttpApiAccessLoggingBadExamples,
			Links:               cloudFormationEnableHttpApiAccessLoggingLinks,
			RemediationMarkdown: cloudFormationEnableHttpApiAccessLoggingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, api := range s.AWS.SAM.HttpAPIs {
			if api.IsUnmanaged() {
				continue
			}

			if api.AccessLogging.CloudwatchLogGroupARN.IsEmpty() {
				results.Add(
					"Access logging is not configured.",
					api.AccessLogging.CloudwatchLogGroupARN,
				)
			} else {
				results.AddPassed(&api)
			}
		}

		return
	},
)
