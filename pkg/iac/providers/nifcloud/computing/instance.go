package computing

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Instance struct {
	Metadata          defsecTypes.Metadata
	SecurityGroup     defsecTypes.StringValue
	NetworkInterfaces []NetworkInterface
}

type NetworkInterface struct {
	Metadata  defsecTypes.Metadata
	NetworkID defsecTypes.StringValue
}
