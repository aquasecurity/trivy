package sam

import (
	"github.com/liamg/iamgo"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sam"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func getStateMachines(cfFile parser.FileContext) (stateMachines []sam.StateMachine) {

	stateMachineResources := cfFile.GetResourcesByType("AWS::Serverless::StateMachine")
	for _, r := range stateMachineResources {
		stateMachine := sam.StateMachine{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("Name"),
			LoggingConfiguration: sam.LoggingConfiguration{
				Metadata:       r.Metadata(),
				LoggingEnabled: iacTypes.BoolDefault(false, r.Metadata()),
			},
			ManagedPolicies: nil,
			Policies:        nil,
			Tracing:         getTracingConfiguration(r),
		}

		// TODO: By default, the level is set to OFF
		if logging := r.GetProperty("Logging"); logging.IsNotNil() {
			stateMachine.LoggingConfiguration.Metadata = logging.Metadata()
			if level := logging.GetProperty("Level"); level.IsNotNil() {
				stateMachine.LoggingConfiguration.LoggingEnabled = iacTypes.Bool(!level.EqualTo("OFF"), level.Metadata())
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
			Enabled:  iacTypes.BoolDefault(false, r.Metadata()),
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
					Name:     iacTypes.StringDefault("", property.Metadata()),
					Document: iam.Document{
						Metadata: property.Metadata(),
						Parsed:   *parsed,
					},
					Builtin: iacTypes.Bool(false, property.Metadata()),
				}
				stateMachine.Policies = append(stateMachine.Policies, policy)
			}
		}
	}
}
