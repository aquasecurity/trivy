package ec2

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/owenrumney/squealer/pkg/squealer"
)

type Instance struct {
	Metadata        defsecTypes.Metadata
	MetadataOptions MetadataOptions
	UserData        defsecTypes.StringValue
	SecurityGroups  []SecurityGroup
	RootBlockDevice *BlockDevice
	EBSBlockDevices []*BlockDevice
}

type BlockDevice struct {
	Metadata  defsecTypes.Metadata
	Encrypted defsecTypes.BoolValue
}

type MetadataOptions struct {
	Metadata     defsecTypes.Metadata
	HttpTokens   defsecTypes.StringValue
	HttpEndpoint defsecTypes.StringValue
}

func NewInstance(metadata defsecTypes.Metadata) *Instance {
	return &Instance{
		Metadata: metadata,
		MetadataOptions: MetadataOptions{
			Metadata:     metadata,
			HttpTokens:   defsecTypes.StringDefault("optional", metadata),
			HttpEndpoint: defsecTypes.StringDefault("enabled", metadata),
		},
		UserData:        defsecTypes.StringDefault("", metadata),
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
