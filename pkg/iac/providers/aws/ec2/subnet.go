package ec2

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Subnet struct {
	Metadata            defsecTypes.Metadata
	MapPublicIpOnLaunch defsecTypes.BoolValue
}
