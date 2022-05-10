package lambda

import "github.com/aquasecurity/defsec/parsers/types"

type Lambda struct {
	types.Metadata
	Functions []Function
}

type Function struct {
	types.Metadata
	Tracing     Tracing
	Permissions []Permission
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Tracing struct {
	types.Metadata
	Mode types.StringValue
}

type Permission struct {
	types.Metadata
	Principal types.StringValue
	SourceARN types.StringValue
}
