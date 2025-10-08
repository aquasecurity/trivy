package ec2

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Subnet struct {
	Metadata            iacTypes.Metadata
	MapPublicIpOnLaunch iacTypes.BoolValue
}
