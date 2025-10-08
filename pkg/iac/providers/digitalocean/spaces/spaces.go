package spaces

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Spaces struct {
	Buckets []Bucket
}

type Bucket struct {
	Metadata     iacTypes.Metadata
	Name         iacTypes.StringValue
	Objects      []Object
	ACL          iacTypes.StringValue
	ForceDestroy iacTypes.BoolValue
	Versioning   Versioning
}

type Versioning struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

type Object struct {
	Metadata iacTypes.Metadata
	ACL      iacTypes.StringValue
}
