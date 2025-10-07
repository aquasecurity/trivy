package network

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Router struct {
	Metadata          iacTypes.Metadata
	SecurityGroup     iacTypes.StringValue
	NetworkInterfaces []NetworkInterface
}
