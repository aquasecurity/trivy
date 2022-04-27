package sam

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableStateMachineLogging = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0119",
		Provider:    providers.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-state-machine-logging",
		Summary:     "SAM State machine must have logging enabled",
		Impact:      "Without logging enabled it is difficult to identify suspicious activity",
		Resolution:  "Enable logging",
		Explanation: `Logging enables end-to-end debugging and analysis of all state machine activities.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-logging",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, stateMachine := range s.AWS.SAM.StateMachines {
			if stateMachine.IsUnmanaged() {
				continue
			}

			if stateMachine.LoggingConfiguration.LoggingEnabled.IsFalse() {
				results.Add(
					"Logging is not enabled,",
					stateMachine.LoggingConfiguration.LoggingEnabled,
				)
			} else {
				results.AddPassed(&stateMachine)
			}
		}
		return
	},
)
