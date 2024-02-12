package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SubNetwork struct {
	Metadata       defsecTypes.Metadata
	Name           defsecTypes.StringValue
	Purpose        defsecTypes.StringValue
	EnableFlowLogs defsecTypes.BoolValue
}
