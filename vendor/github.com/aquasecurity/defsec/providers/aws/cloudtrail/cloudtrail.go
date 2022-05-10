package cloudtrail

import "github.com/aquasecurity/defsec/parsers/types"

type CloudTrail struct {
	types.Metadata
	Trails []Trail
}

type Trail struct {
	types.Metadata
	Name                    types.StringValue
	EnableLogFileValidation types.BoolValue
	IsMultiRegion           types.BoolValue
	KMSKeyID                types.StringValue
}
