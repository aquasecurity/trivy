package s3

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type PublicAccessBlock struct {
	Metadata              defsecTypes.MisconfigMetadata
	BlockPublicACLs       defsecTypes.BoolValue
	BlockPublicPolicy     defsecTypes.BoolValue
	IgnorePublicACLs      defsecTypes.BoolValue
	RestrictPublicBuckets defsecTypes.BoolValue
}

func NewPublicAccessBlock(metadata defsecTypes.MisconfigMetadata) PublicAccessBlock {
	return PublicAccessBlock{
		Metadata:              metadata,
		BlockPublicPolicy:     defsecTypes.BoolDefault(false, metadata),
		BlockPublicACLs:       defsecTypes.BoolDefault(false, metadata),
		IgnorePublicACLs:      defsecTypes.BoolDefault(false, metadata),
		RestrictPublicBuckets: defsecTypes.BoolDefault(false, metadata),
	}
}
