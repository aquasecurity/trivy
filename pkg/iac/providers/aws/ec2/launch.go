package ec2

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type LaunchConfiguration struct {
	Metadata          iacTypes.Metadata
	Name              iacTypes.StringValue
	AssociatePublicIP iacTypes.BoolValue
	RootBlockDevice   *BlockDevice
	EBSBlockDevices   []*BlockDevice
	MetadataOptions   MetadataOptions
	UserData          iacTypes.StringValue
}

type LaunchTemplate struct {
	Metadata iacTypes.Metadata
	Name     iacTypes.StringValue
	Instance
}

func (i *LaunchConfiguration) RequiresIMDSToken() bool {
	return i.MetadataOptions.HttpTokens.EqualTo("required")
}

func (i *LaunchConfiguration) HasHTTPEndpointDisabled() bool {
	return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
}
