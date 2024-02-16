package network

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type VpnGateway struct {
	Metadata      iacTypes.Metadata
	SecurityGroup iacTypes.StringValue
}
