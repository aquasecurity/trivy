package types

import (
	"encoding/json"
)

type IntValue interface {
	metadataProvider
	Value() int
	EqualTo(i int) bool
	NotEqualTo(i int) bool
	LessThan(i int) bool
	GreaterThan(i int) bool
}

type intValue struct {
	BaseAttribute
	value int
}

func (v *intValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func Int(value int, m Metadata) IntValue {
	return &intValue{
		value:         value,
		BaseAttribute: BaseAttribute{metadata: m},
	}
}

func IntDefault(value int, m Metadata) IntValue {
	b := Int(value, m)
	b.(*intValue).BaseAttribute.metadata.isDefault = true
	return b
}

func IntUnresolvable(m Metadata) IntValue {
	b := Int(0, m)
	b.(*intValue).BaseAttribute.metadata.isUnresolvable = true
	return b
}

func IntExplicit(value int, m Metadata) IntValue {
	b := Int(value, m)
	b.(*intValue).BaseAttribute.metadata.isExplicit = true
	return b
}

func (b *intValue) GetMetadata() Metadata {
	return b.metadata
}

func (b *intValue) Value() int {
	return b.value
}

func (b *intValue) GetRawValue() interface{} {
	return b.value
}

func (b *intValue) NotEqualTo(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value != i
}

func (b *intValue) EqualTo(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value == i
}

func (b *intValue) LessThan(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value < i
}

func (b *intValue) GreaterThan(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value > i
}

func (s *intValue) ToRego() interface{} {
	return map[string]interface{}{
		"filepath":  s.metadata.Range().GetFilename(),
		"startline": s.metadata.Range().GetStartLine(),
		"endline":   s.metadata.Range().GetEndLine(),
		"managed":   s.metadata.isManaged,
		"explicit":  s.metadata.isExplicit,
		"value":     s.Value(),
		"fskey":     CreateFSKey(s.metadata.Range().GetFS()),
		"resource":  s.metadata.Reference().String(),
	}
}
