package autoscaling

import (
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/ec2"
)

type Autoscaling struct {
	types.Metadata
	LaunchConfigurations []LaunchConfiguration
	LaunchTemplates      []LaunchTemplate
}

type LaunchConfiguration struct {
	types.Metadata
	Name              types.StringValue
	AssociatePublicIP types.BoolValue
	RootBlockDevice   *ec2.BlockDevice
	EBSBlockDevices   []ec2.BlockDevice
	MetadataOptions   ec2.MetadataOptions
	UserData          types.StringValue
}

type LaunchTemplate struct {
	types.Metadata
	ec2.Instance
}

func (i *LaunchConfiguration) RequiresIMDSToken() bool {
	if i.MetadataOptions.HttpTokens != nil {
		return i.MetadataOptions.HttpTokens.EqualTo("required")
	}
	return false
}

func (i *LaunchConfiguration) HasHTTPEndpointDisabled() bool {
	if i.MetadataOptions.HttpEndpoint != nil {
		return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
	}
	return false
}
