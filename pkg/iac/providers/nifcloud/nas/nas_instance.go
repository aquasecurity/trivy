package nas

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type NASInstance struct {
	Metadata  defsecTypes.Metadata
	NetworkID defsecTypes.StringValue
}
