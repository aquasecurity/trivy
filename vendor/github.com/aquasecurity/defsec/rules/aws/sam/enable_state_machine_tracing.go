package sam

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableStateMachineTracing = rules.Register(
	rules.Rule{
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
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableStateMachineTracingGoodExamples,
			BadExamples:         cloudFormationEnableStateMachineTracingBadExamples,
			Links:               cloudFormationEnableStateMachineTracingLinks,
			RemediationMarkdown: cloudFormationEnableStateMachineTracingRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
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
