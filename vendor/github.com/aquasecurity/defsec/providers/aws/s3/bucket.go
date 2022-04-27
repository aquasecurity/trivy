package s3

import "github.com/aquasecurity/defsec/parsers/types"

type Bucket struct {
	types.Metadata
	Name              types.StringValue
	PublicAccessBlock *PublicAccessBlock
	BucketPolicy      BucketPolicy
	Encryption        Encryption
	Versioning        Versioning
	Logging           Logging
	ACL               types.StringValue
}

func (b *Bucket) HasPublicExposureACL() bool {
	for _, publicACL := range []string{"public-read", "public-read-write", "website", "authenticated-read"} {
		if b.ACL.EqualTo(publicACL) {
			// if there is a public access block, check the public ACL blocks
			if b.PublicAccessBlock != nil && b.PublicAccessBlock.IsManaged() {
				return b.PublicAccessBlock.IgnorePublicACLs.IsFalse() && b.PublicAccessBlock.BlockPublicACLs.IsFalse()
			}
			return true
		}
	}
	return false
}

type BucketPolicy struct {
	types.Metadata
}

type Logging struct {
	types.Metadata
	Enabled      types.BoolValue
	TargetBucket types.StringValue
}

type Versioning struct {
	types.Metadata
	Enabled types.BoolValue
}

type Encryption struct {
	types.Metadata
	Enabled   types.BoolValue
	Algorithm types.StringValue
	KMSKeyId  types.StringValue
}
