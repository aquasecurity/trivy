package spaces

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Spaces struct {
	Buckets []Bucket
}

type Bucket struct {
	Metadata     defsecTypes.MisconfigMetadata
	Name         defsecTypes.StringValue
	Objects      []Object
	ACL          defsecTypes.StringValue
	ForceDestroy defsecTypes.BoolValue
	Versioning   Versioning
}

type Versioning struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}

type Object struct {
	Metadata defsecTypes.MisconfigMetadata
	ACL      defsecTypes.StringValue
}
