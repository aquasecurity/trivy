package ec2

import (
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
