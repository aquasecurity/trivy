package compute

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type SubNetwork struct {
	types.Metadata
	Name           types.StringValue
	EnableFlowLogs types.BoolValue
}
