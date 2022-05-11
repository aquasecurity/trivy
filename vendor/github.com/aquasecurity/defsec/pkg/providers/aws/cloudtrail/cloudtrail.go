package cloudtrail

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type CloudTrail struct {
	Trails []Trail
}

type Trail struct {
	types.Metadata
	Name                    types.StringValue
	EnableLogFileValidation types.BoolValue
	IsMultiRegion           types.BoolValue
	KMSKeyID                types.StringValue
}
