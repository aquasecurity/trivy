package network

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Router struct {
	Metadata          defsecTypes.MisconfigMetadata
	SecurityGroup     defsecTypes.StringValue
	NetworkInterfaces []NetworkInterface
}
