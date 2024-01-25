package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type SubNetwork struct {
	Metadata       defsecTypes.MisconfigMetadata
	Name           defsecTypes.StringValue
	Purpose        defsecTypes.StringValue
	EnableFlowLogs defsecTypes.BoolValue
}
