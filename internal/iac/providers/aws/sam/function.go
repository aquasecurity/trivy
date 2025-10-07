package sam

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Function struct {
	Metadata        iacTypes.Metadata
	FunctionName    iacTypes.StringValue
	Tracing         iacTypes.StringValue
	ManagedPolicies []iacTypes.StringValue
	Policies        []iam.Policy
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Permission struct {
	Metadata  iacTypes.Metadata
	Principal iacTypes.StringValue
	SourceARN iacTypes.StringValue
}
