package sam

import (
	"github.com/aquasecurity/trivy/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type StateMachine struct {
	Metadata             defsecTypes.MisconfigMetadata
	Name                 defsecTypes.StringValue
	LoggingConfiguration LoggingConfiguration
	ManagedPolicies      []defsecTypes.StringValue
	Policies             []iam.Policy
	Tracing              TracingConfiguration
}

type LoggingConfiguration struct {
	Metadata       defsecTypes.MisconfigMetadata
	LoggingEnabled defsecTypes.BoolValue
}

type TracingConfiguration struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}
