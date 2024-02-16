package ec2

import (
	"github.com/owenrumney/squealer/pkg/squealer"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Instance struct {
	Metadata        iacTypes.Metadata
	MetadataOptions MetadataOptions
	UserData        iacTypes.StringValue
	SecurityGroups  []SecurityGroup
	RootBlockDevice *BlockDevice
	EBSBlockDevices []*BlockDevice
}

type BlockDevice struct {
	Metadata  iacTypes.Metadata
	Encrypted iacTypes.BoolValue
}

type MetadataOptions struct {
	Metadata     iacTypes.Metadata
	HttpTokens   iacTypes.StringValue
	HttpEndpoint iacTypes.StringValue
}

func NewInstance(metadata iacTypes.Metadata) *Instance {
	return &Instance{
		Metadata: metadata,
		MetadataOptions: MetadataOptions{
			Metadata:     metadata,
			HttpTokens:   iacTypes.StringDefault("optional", metadata),
			HttpEndpoint: iacTypes.StringDefault("enabled", metadata),
		},
		UserData:        iacTypes.StringDefault("", metadata),
		SecurityGroups:  []SecurityGroup{},
		RootBlockDevice: nil,
		EBSBlockDevices: nil,
	}
}

func (i *Instance) RequiresIMDSToken() bool {
	return i.MetadataOptions.HttpTokens.EqualTo("required")
}

func (i *Instance) HasHTTPEndpointDisabled() bool {
	return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
}

func (i *Instance) HasSensitiveInformationInUserData() bool {
	scanner := squealer.NewStringScanner()
	return scanner.Scan(i.UserData.Value()).TransgressionFound
}
