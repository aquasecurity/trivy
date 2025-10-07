package s3

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Bucket struct {
	Metadata                      iacTypes.Metadata
	Name                          iacTypes.StringValue
	PublicAccessBlock             *PublicAccessBlock
	BucketPolicies                []iam.Policy
	Encryption                    Encryption
	Versioning                    Versioning
	Logging                       Logging
	ACL                           iacTypes.StringValue
	Grants                        []Grant
	BucketLocation                iacTypes.StringValue
	AccelerateConfigurationStatus iacTypes.StringValue
	LifecycleConfiguration        []Rules
	Objects                       []Contents
	Website                       *Website
}

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

type Logging struct {
	Metadata     iacTypes.Metadata
	Enabled      iacTypes.BoolValue
	TargetBucket iacTypes.StringValue
}

type Versioning struct {
	Metadata  iacTypes.Metadata
	Enabled   iacTypes.BoolValue
	MFADelete iacTypes.BoolValue
}

type Encryption struct {
	Metadata  iacTypes.Metadata
	Enabled   iacTypes.BoolValue
	Algorithm iacTypes.StringValue
	KMSKeyId  iacTypes.StringValue
}

type Rules struct {
	Metadata iacTypes.Metadata
	Status   iacTypes.StringValue
}

type Contents struct {
	Metadata iacTypes.Metadata
}

type Website struct {
	Metadata iacTypes.Metadata
}

type Grant struct {
	Metadata    iacTypes.Metadata
	Grantee     Grantee
	Permissions iacTypes.StringValueList
}

type Grantee struct {
	Metadata iacTypes.Metadata
	URI      iacTypes.StringValue
	Type     iacTypes.StringValue
}
