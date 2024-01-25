package ec2

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type LaunchConfiguration struct {
	Metadata          defsecTypes.MisconfigMetadata
	Name              defsecTypes.StringValue
	AssociatePublicIP defsecTypes.BoolValue
	RootBlockDevice   *BlockDevice
	EBSBlockDevices   []*BlockDevice
	MetadataOptions   MetadataOptions
	UserData          defsecTypes.StringValue
}

type LaunchTemplate struct {
	Metadata defsecTypes.MisconfigMetadata
	Name     defsecTypes.StringValue
	Instance
}

func (i *LaunchConfiguration) RequiresIMDSToken() bool {
	return i.MetadataOptions.HttpTokens.EqualTo("required")
}

func (i *LaunchConfiguration) HasHTTPEndpointDisabled() bool {
	return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
}
