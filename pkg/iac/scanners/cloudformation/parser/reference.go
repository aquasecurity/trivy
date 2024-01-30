package parser

import (
	"fmt"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type CFReference struct {
	logicalId     string
	resourceRange defsecTypes.Range
	resolvedValue Property
}

func NewCFReference(id string, resourceRange defsecTypes.Range) CFReference {
	return CFReference{
		logicalId:     id,
		resourceRange: resourceRange,
	}
}

func NewCFReferenceWithValue(resourceRange defsecTypes.Range, resolvedValue Property, logicalId string) CFReference {
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

func (cf CFReference) ResourceRange() defsecTypes.Range {
	return cf.resourceRange
}

func (cf CFReference) PropertyRange() defsecTypes.Range {
	if cf.resolvedValue.IsNotNil() {
		return cf.resolvedValue.Range()
	}
	return defsecTypes.Range{}
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
