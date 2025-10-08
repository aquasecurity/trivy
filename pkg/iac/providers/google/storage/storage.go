package storage

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Storage struct {
	Buckets []Bucket
}

type Bucket struct {
	Metadata                       iacTypes.Metadata
	Name                           iacTypes.StringValue
	Location                       iacTypes.StringValue
	EnableUniformBucketLevelAccess iacTypes.BoolValue
	Members                        []iam.Member
	Bindings                       []iam.Binding
	Encryption                     BucketEncryption
	Logging                        BucketLogging
	Versioning                     BucketVersioning
}

type BucketEncryption struct {
	Metadata          iacTypes.Metadata
	DefaultKMSKeyName iacTypes.StringValue
}

type BucketLogging struct {
	Metadata        iacTypes.Metadata
	LogBucket       iacTypes.StringValue
	LogObjectPrefix iacTypes.StringValue
}

type BucketVersioning struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}
