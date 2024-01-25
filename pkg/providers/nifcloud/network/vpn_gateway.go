package network

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type VpnGateway struct {
	Metadata      defsecTypes.MisconfigMetadata
	SecurityGroup defsecTypes.StringValue
}
