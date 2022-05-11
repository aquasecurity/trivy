package parser

import (
	"fmt"

	"github.com/aquasecurity/defsec/internal/types"
)

type CFReference struct {
	logicalId     string
	resourceRange types.Range
	resolvedValue Property
}

func NewCFReference(id string, resourceRange types.Range) types.Reference {
	return &CFReference{
		logicalId:     id,
		resourceRange: resourceRange,
	}
}

func NewCFReferenceWithValue(resourceRange types.Range, resolvedValue Property, logicalId string) types.Reference {
	return &CFReference{
		resourceRange: resourceRange,
		resolvedValue: resolvedValue,
		logicalId:     logicalId,
	}
}

func (cf *CFReference) String() string {
	return cf.resourceRange.String()
}

func (cf *CFReference) LogicalID() string {
	return cf.logicalId
}

func (cf *CFReference) RefersTo(r types.Reference) bool {
	return false
}

func (cf *CFReference) ResourceRange() types.Range {
	return cf.resourceRange
}

func (cf *CFReference) PropertyRange() types.Range {
	if cf.resolvedValue.IsNotNil() {
		return cf.resolvedValue.Range()
	}
	return nil
}

func (cf *CFReference) DisplayValue() string {
	if cf.resolvedValue.IsNotNil() {
		return fmt.Sprintf("%v", cf.resolvedValue.RawValue())
	}
	return ""
}

func (cf *CFReference) Comment() string {
	return cf.resolvedValue.Comment()
}
