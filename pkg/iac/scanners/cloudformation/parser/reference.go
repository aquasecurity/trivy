package parser

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type CFReference struct {
	logicalId     string
	resourceRange iacTypes.Range
}

func NewCFReference(id string, resourceRange iacTypes.Range) CFReference {
	return CFReference{
		logicalId:     id,
		resourceRange: resourceRange,
	}
}

func (cf CFReference) String() string {
	return cf.resourceRange.String()
}
