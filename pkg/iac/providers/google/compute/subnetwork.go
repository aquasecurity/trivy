package compute

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SubNetwork struct {
	Metadata       iacTypes.Metadata
	Name           iacTypes.StringValue
	Purpose        iacTypes.StringValue
	EnableFlowLogs iacTypes.BoolValue
}
