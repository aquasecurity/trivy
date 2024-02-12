package storage

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Storage struct {
	Buckets []Bucket
}

type Bucket struct {
	Metadata                       defsecTypes.Metadata
	Name                           defsecTypes.StringValue
	Location                       defsecTypes.StringValue
	EnableUniformBucketLevelAccess defsecTypes.BoolValue
	Members                        []iam.Member
	Bindings                       []iam.Binding
	Encryption                     BucketEncryption
}

type BucketEncryption struct {
	Metadata          defsecTypes.Metadata
	DefaultKMSKeyName defsecTypes.StringValue
}
