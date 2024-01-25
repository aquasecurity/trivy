package lambda

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Lambda struct {
	Functions []Function
}

type Function struct {
	Metadata    defsecTypes.MisconfigMetadata
	Tracing     Tracing
	Permissions []Permission
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Tracing struct {
	Metadata defsecTypes.MisconfigMetadata
	Mode     defsecTypes.StringValue
}

type Permission struct {
	Metadata  defsecTypes.MisconfigMetadata
	Principal defsecTypes.StringValue
	SourceARN defsecTypes.StringValue
}
