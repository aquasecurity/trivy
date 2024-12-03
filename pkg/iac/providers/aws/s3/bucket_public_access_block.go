package s3

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type PublicAccessBlock struct {
	Metadata              iacTypes.Metadata
	BlockPublicACLs       iacTypes.BoolValue
	BlockPublicPolicy     iacTypes.BoolValue
	IgnorePublicACLs      iacTypes.BoolValue
	RestrictPublicBuckets iacTypes.BoolValue
}

func NewPublicAccessBlock(metadata iacTypes.Metadata) PublicAccessBlock {
	return PublicAccessBlock{
		Metadata:              metadata,
		BlockPublicPolicy:     iacTypes.BoolDefault(false, metadata),
		BlockPublicACLs:       iacTypes.BoolDefault(false, metadata),
		IgnorePublicACLs:      iacTypes.BoolDefault(false, metadata),
		RestrictPublicBuckets: iacTypes.BoolDefault(false, metadata),
	}
}
