package sam

import (
	"github.com/aquasecurity/trivy/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Function struct {
	Metadata        defsecTypes.MisconfigMetadata
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
	Metadata  defsecTypes.MisconfigMetadata
	Principal defsecTypes.StringValue
	SourceARN defsecTypes.StringValue
}
