package types

import "encoding/json"

type BoolValue interface {
	metadataProvider
	Value() bool
	IsTrue() bool
	IsFalse() bool
}

type boolValue struct {
	BaseAttribute
	value bool
}

func (b *boolValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.value)
}

func Bool(value bool, metadata Metadata) BoolValue {
	return &boolValue{
		value:         value,
		BaseAttribute: BaseAttribute{metadata: metadata},
	}
}

func BoolDefault(value bool, metadata Metadata) BoolValue {
	b := Bool(value, metadata)
	b.(*boolValue).BaseAttribute.metadata.isDefault = true
	return b
}

func BoolUnresolvable(m Metadata) BoolValue {
	b := Bool(false, m)
	b.(*boolValue).BaseAttribute.metadata.isUnresolvable = true
	return b
}

func BoolExplicit(value bool, metadata Metadata) BoolValue {
	b := Bool(value, metadata)
	b.(*boolValue).BaseAttribute.metadata.isExplicit = true
	return b
}

func (b *boolValue) Value() bool {
	return b.value
}

func (b *boolValue) GetRawValue() interface{} {
	return b.value
}

func (b *boolValue) IsTrue() bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.Value()
}

func (b *boolValue) IsFalse() bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return !b.Value()
}

func (s *boolValue) ToRego() interface{} {
	return map[string]interface{}{
		"filepath":  s.metadata.Range().GetFilename(),
		"startline": s.metadata.Range().GetStartLine(),
		"endline":   s.metadata.Range().GetEndLine(),
		"managed":   s.metadata.isManaged,
		"explicit":  s.metadata.isExplicit,
		"value":     s.Value(),
	}
}
