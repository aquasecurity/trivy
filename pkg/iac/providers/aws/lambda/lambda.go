package lambda

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Lambda struct {
	Functions []Function
}

type Function struct {
	Metadata    defsecTypes.Metadata
	Tracing     Tracing
	Permissions []Permission
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Tracing struct {
	Metadata defsecTypes.Metadata
	Mode     defsecTypes.StringValue
}

type Permission struct {
	Metadata  defsecTypes.Metadata
	Principal defsecTypes.StringValue
	SourceARN defsecTypes.StringValue
}
