package s3

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Bucket struct {
	Metadata                      defsecTypes.Metadata
	Name                          defsecTypes.StringValue
	PublicAccessBlock             *PublicAccessBlock
	BucketPolicies                []iam.Policy
	Encryption                    Encryption
	Versioning                    Versioning
	Logging                       Logging
	ACL                           defsecTypes.StringValue
	BucketLocation                defsecTypes.StringValue
	AccelerateConfigurationStatus defsecTypes.StringValue
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
	Metadata     defsecTypes.Metadata
	Enabled      defsecTypes.BoolValue
	TargetBucket defsecTypes.StringValue
}

type Versioning struct {
	Metadata  defsecTypes.Metadata
	Enabled   defsecTypes.BoolValue
	MFADelete defsecTypes.BoolValue
}

type Encryption struct {
	Metadata  defsecTypes.Metadata
	Enabled   defsecTypes.BoolValue
	Algorithm defsecTypes.StringValue
	KMSKeyId  defsecTypes.StringValue
}

type Rules struct {
	Metadata defsecTypes.Metadata
	Status   defsecTypes.StringValue
}

type Contents struct {
	Metadata defsecTypes.Metadata
}

type Website struct {
	Metadata defsecTypes.Metadata
}
