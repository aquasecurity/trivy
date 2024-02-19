package parser

import (
	"fmt"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type CFReference struct {
	logicalId     string
	resourceRange iacTypes.Range
	resolvedValue Property
}

func NewCFReference(id string, resourceRange iacTypes.Range) CFReference {
	return CFReference{
		logicalId:     id,
		resourceRange: resourceRange,
	}
}

func NewCFReferenceWithValue(resourceRange iacTypes.Range, resolvedValue Property, logicalId string) CFReference {
	return CFReference{
		resourceRange: resourceRange,
		resolvedValue: resolvedValue,
		logicalId:     logicalId,
	}
}

func (cf CFReference) String() string {
	return cf.resourceRange.String()
}

func (cf CFReference) LogicalID() string {
	return cf.logicalId
}

func (cf CFReference) ResourceRange() iacTypes.Range {
	return cf.resourceRange
}

func (cf CFReference) PropertyRange() iacTypes.Range {
	if cf.resolvedValue.IsNotNil() {
		return cf.resolvedValue.Range()
	}
	return iacTypes.Range{}
}

func (cf CFReference) DisplayValue() string {
	if cf.resolvedValue.IsNotNil() {
		return fmt.Sprintf("%v", cf.resolvedValue.RawValue())
	}
	return ""
}

func (cf *CFReference) Comment() string {
	return cf.resolvedValue.Comment()
}
