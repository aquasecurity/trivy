package storage

import (
	"github.com/aquasecurity/trivy/pkg/providers/google/iam"
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Storage struct {
	Buckets []Bucket
}

type Bucket struct {
	Metadata                       defsecTypes.MisconfigMetadata
	Name                           defsecTypes.StringValue
	Location                       defsecTypes.StringValue
	EnableUniformBucketLevelAccess defsecTypes.BoolValue
	Members                        []iam.Member
	Bindings                       []iam.Binding
	Encryption                     BucketEncryption
}

type BucketEncryption struct {
	Metadata          defsecTypes.MisconfigMetadata
	DefaultKMSKeyName defsecTypes.StringValue
}
