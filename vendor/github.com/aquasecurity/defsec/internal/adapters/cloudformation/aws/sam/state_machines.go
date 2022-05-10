package sam

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/liamg/iamgo"
)

func getStateMachines(cfFile parser.FileContext) (stateMachines []sam.StateMachine) {

	stateMachineResources := cfFile.GetResourcesByType("AWS::Serverless::StateMachine")
	for _, r := range stateMachineResources {
		stateMachine := sam.StateMachine{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("Name"),
			LoggingConfiguration: sam.LoggingConfiguration{
				Metadata:       r.Metadata(),
				LoggingEnabled: types.BoolDefault(false, r.Metadata()),
			},
			ManagedPolicies: nil,
			Policies:        nil,
			Tracing:         getTracingConfiguration(r),
		}

		if logging := r.GetProperty("Logging"); logging.IsNotNil() {
			stateMachine.LoggingConfiguration.Metadata = logging.Metadata()
			if level := logging.GetProperty("Level"); level.IsNotNil() {
				stateMachine.LoggingConfiguration.LoggingEnabled = types.Bool(!level.EqualTo("OFF"), level.Metadata())
			}
		}

		setStateMachinePolicies(r, &stateMachine)
		stateMachines = append(stateMachines, stateMachine)
	}

	return stateMachines
}

func getTracingConfiguration(r *parser.Resource) sam.TracingConfiguration {
	tracing := r.GetProperty("Tracing")
	if tracing.IsNil() {
		return sam.TracingConfiguration{
			Metadata: r.Metadata(),
			Enabled:  types.BoolDefault(false, r.Metadata()),
		}
	}

	return sam.TracingConfiguration{
		Metadata: tracing.Metadata(),
		Enabled:  tracing.GetBoolProperty("Enabled"),
	}
}

func setStateMachinePolicies(r *parser.Resource, stateMachine *sam.StateMachine) {
	policies := r.GetProperty("Policies")
	if policies.IsNotNil() {
		if policies.IsString() {
			stateMachine.ManagedPolicies = append(stateMachine.ManagedPolicies, policies.AsStringValue())
		} else if policies.IsList() {
			for _, property := range policies.AsList() {
				parsed, err := iamgo.Parse(property.GetJsonBytes(true))
				if err != nil {
					continue
				}
				policy := iam.Policy{
					Metadata: property.Metadata(),
					Document: iam.Document{
						Metadata: property.Metadata(),
						Parsed:   *parsed,
					},
				}
				stateMachine.Policies = append(stateMachine.Policies, policy)
			}
		}
	}
}
