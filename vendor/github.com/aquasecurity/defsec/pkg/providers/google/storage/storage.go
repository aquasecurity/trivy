package storage

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
)

type Storage struct {
	Buckets []Bucket
}

type Bucket struct {
	types.Metadata
	Name                           types.StringValue
	Location                       types.StringValue
	EnableUniformBucketLevelAccess types.BoolValue
	Members                        []iam.Member
	Bindings                       []iam.Binding
}
