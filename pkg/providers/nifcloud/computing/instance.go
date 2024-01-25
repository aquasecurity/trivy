package computing

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Instance struct {
	Metadata          defsecTypes.MisconfigMetadata
	SecurityGroup     defsecTypes.StringValue
	NetworkInterfaces []NetworkInterface
}

type NetworkInterface struct {
	Metadata  defsecTypes.MisconfigMetadata
	NetworkID defsecTypes.StringValue
}
