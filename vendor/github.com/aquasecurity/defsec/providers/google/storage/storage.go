package storage

import (
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/iam"
)

type Storage struct {
	types.Metadata
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
