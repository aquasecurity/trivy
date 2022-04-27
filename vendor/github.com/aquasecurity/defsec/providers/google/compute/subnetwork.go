package compute

import "github.com/aquasecurity/defsec/parsers/types"

type SubNetwork struct {
	types.Metadata
	Name           types.StringValue
	EnableFlowLogs types.BoolValue
}
