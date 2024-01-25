package nas

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type NASInstance struct {
	Metadata  defsecTypes.MisconfigMetadata
	NetworkID defsecTypes.StringValue
}
