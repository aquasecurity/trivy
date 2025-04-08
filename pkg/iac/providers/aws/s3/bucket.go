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

func (b *Bucket) HasPublicExposureACL() bool {
	for _, publicACL := range []string{"public-read", "public-read-write", "website", "authenticated-read"} {
		if b.ACL.EqualTo(publicACL) {
			// if there is a public access block, check the public ACL blocks
			if b.PublicAccessBlock != nil && b.PublicAccessBlock.Metadata.IsManaged() {
				return b.PublicAccessBlock.IgnorePublicACLs.IsFalse() && b.PublicAccessBlock.BlockPublicACLs.IsFalse()
			}
			return true
		}
	}
	return false
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
