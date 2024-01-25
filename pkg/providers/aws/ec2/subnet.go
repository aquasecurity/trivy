package ec2

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Subnet struct {
	Metadata            defsecTypes.MisconfigMetadata
	MapPublicIpOnLaunch defsecTypes.BoolValue
}
