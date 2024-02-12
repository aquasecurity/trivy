package network

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type VpnGateway struct {
	Metadata      defsecTypes.Metadata
	SecurityGroup defsecTypes.StringValue
}
