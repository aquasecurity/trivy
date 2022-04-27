package ec2

import (
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/vpc"
	"github.com/owenrumney/squealer/pkg/squealer"
)

type Instance struct {
	types.Metadata
	MetadataOptions MetadataOptions
	UserData        types.StringValue
	SecurityGroups  []vpc.SecurityGroup
	RootBlockDevice *BlockDevice
	EBSBlockDevices []BlockDevice
}

type BlockDevice struct {
	types.Metadata
	Encrypted types.BoolValue
}

type MetadataOptions struct {
	types.Metadata
	HttpTokens   types.StringValue
	HttpEndpoint types.StringValue
}

func (i *Instance) RequiresIMDSToken() bool {
	if i.MetadataOptions.HttpTokens != nil {
		return i.MetadataOptions.HttpTokens.EqualTo("required")
	}
	return false
}

func (i *Instance) HasHTTPEndpointDisabled() bool {
	if i.MetadataOptions.HttpEndpoint != nil {
		return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
	}
	return false
}

func (i *Instance) HasSensitiveInformationInUserData() bool {
	if i.UserData == nil {
		return false
	}
	scanner := squealer.NewStringScanner()
	return scanner.Scan(i.UserData.Value()).TransgressionFound
}
