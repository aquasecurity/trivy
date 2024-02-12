package sam

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Function struct {
	Metadata        defsecTypes.Metadata
	FunctionName    defsecTypes.StringValue
	Tracing         defsecTypes.StringValue
	ManagedPolicies []defsecTypes.StringValue
	Policies        []iam.Policy
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Permission struct {
	Metadata  defsecTypes.Metadata
	Principal defsecTypes.StringValue
	SourceARN defsecTypes.StringValue
}
