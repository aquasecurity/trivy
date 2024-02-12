package s3

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type PublicAccessBlock struct {
	Metadata              defsecTypes.Metadata
	BlockPublicACLs       defsecTypes.BoolValue
	BlockPublicPolicy     defsecTypes.BoolValue
	IgnorePublicACLs      defsecTypes.BoolValue
	RestrictPublicBuckets defsecTypes.BoolValue
}

func NewPublicAccessBlock(metadata defsecTypes.Metadata) PublicAccessBlock {
	return PublicAccessBlock{
		Metadata:              metadata,
		BlockPublicPolicy:     defsecTypes.BoolDefault(false, metadata),
		BlockPublicACLs:       defsecTypes.BoolDefault(false, metadata),
		IgnorePublicACLs:      defsecTypes.BoolDefault(false, metadata),
		RestrictPublicBuckets: defsecTypes.BoolDefault(false, metadata),
	}
}
