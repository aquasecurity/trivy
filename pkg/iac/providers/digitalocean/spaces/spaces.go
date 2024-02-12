package spaces

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Spaces struct {
	Buckets []Bucket
}

type Bucket struct {
	Metadata     defsecTypes.Metadata
	Name         defsecTypes.StringValue
	Objects      []Object
	ACL          defsecTypes.StringValue
	ForceDestroy defsecTypes.BoolValue
	Versioning   Versioning
}

type Versioning struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type Object struct {
	Metadata defsecTypes.Metadata
	ACL      defsecTypes.StringValue
}
