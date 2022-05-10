package sam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableStateMachineTracing = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0117",
		Provider:    providers.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-state-machine-tracing",
		Summary:     "SAM State machine must have X-Ray tracing enabled",
		Impact:      "Without full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all state machine activities.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-tracing",
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableStateMachineTracingGoodExamples,
			BadExamples:         cloudFormationEnableStateMachineTracingBadExamples,
			Links:               cloudFormationEnableStateMachineTracingLinks,
			RemediationMarkdown: cloudFormationEnableStateMachineTracingRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, stateMachine := range s.AWS.SAM.StateMachines {
			if stateMachine.IsUnmanaged() {
				continue
			}

			if stateMachine.Tracing.Enabled.IsFalse() {
				results.Add(
					"X-Ray tracing is not enabled,",
					stateMachine.Tracing.Enabled,
				)
			} else {
				results.AddPassed(&stateMachine)
			}
		}
		return
	},
)
