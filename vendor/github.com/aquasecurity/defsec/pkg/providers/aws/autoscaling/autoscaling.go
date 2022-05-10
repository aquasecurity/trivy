package autoscaling

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
)

type Autoscaling struct {
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
	return i.MetadataOptions.HttpTokens.EqualTo("required")
}

func (i *LaunchConfiguration) HasHTTPEndpointDisabled() bool {
	return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
}
