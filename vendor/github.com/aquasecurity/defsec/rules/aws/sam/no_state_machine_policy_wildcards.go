package sam

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoStateMachinePolicyWildcards = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0120",
		Provider:    providers.AWSProvider,
		Service:     "sam",
		ShortCode:   "no-state-machine-policy-wildcards",
		Summary:     "State machine policies should avoid use of wildcards and instead apply the principle of least privilege",
		Impact:      "Overly permissive policies may grant access to sensitive resources",
		Resolution:  "Specify the exact permissions required, and to which resources they should apply instead of using wildcards.",
		Explanation: `You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-policies",
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationNoStateMachinePolicyWildcardsGoodExamples,
			BadExamples:         cloudFormationNoStateMachinePolicyWildcardsBadExamples,
			Links:               cloudFormationNoStateMachinePolicyWildcardsLinks,
			RemediationMarkdown: cloudFormationNoStateMachinePolicyWildcardsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {

		for _, stateMachine := range s.AWS.SAM.StateMachines {
			if stateMachine.IsUnmanaged() {
				continue
			}

			for _, document := range stateMachine.Policies {
				policy := document.Document.Parsed
				statements, _ := policy.Statements()
				for _, statement := range statements {
					results = checkStatement(document.Document, statement, results)
				}
			}
		}
		return
	},
)
