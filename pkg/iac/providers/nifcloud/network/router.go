package network

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Router struct {
	Metadata          defsecTypes.Metadata
	SecurityGroup     defsecTypes.StringValue
	NetworkInterfaces []NetworkInterface
}
