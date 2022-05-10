package types

import (
	"encoding/json"
)

type MapValue interface {
	metadataProvider
	Value() map[string]string
	HasKey(key string) bool
	Len() int
}

type mapValue struct {
	BaseAttribute
	value map[string]string
}

func (v *mapValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func Map(value map[string]string, m Metadata) MapValue {
	return &mapValue{
		value:         value,
		BaseAttribute: BaseAttribute{metadata: m},
	}
}

func MapDefault(value map[string]string, m Metadata) MapValue {
	b := Map(value, m)
	b.(*mapValue).BaseAttribute.metadata.isDefault = true
	return b
}

func MapExplicit(value map[string]string, m Metadata) MapValue {
	b := Map(value, m)
	b.(*mapValue).BaseAttribute.metadata.isExplicit = true
	return b
}

func (b *mapValue) Value() map[string]string {
	return b.value
}

func (b *mapValue) GetRawValue() interface{} {
	return b.value
}

func (b *mapValue) Len() int {
	return len(b.value)
}

func (b *mapValue) HasKey(key string) bool {
	if b.value == nil {
		return false
	}
	_, ok := b.value[key]
	return ok
}

func (s *mapValue) ToRego() interface{} {
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
