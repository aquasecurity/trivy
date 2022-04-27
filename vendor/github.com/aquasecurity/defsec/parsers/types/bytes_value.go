package types

import (
	"encoding/json"
)

type BytesValue interface {
	metadataProvider
	Value() []byte
	Len() int
}

type bytesValue struct {
	BaseAttribute
	value []byte
}

func (b *bytesValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.value)
}

func (b *bytesValue) Value() []byte {
	return b.value
}

func (b *bytesValue) GetRawValue() interface{} {
	return b.value
}

func (b *bytesValue) Len() int {
	return len(b.value)
}

func (b *bytesValue) GetMetadata() Metadata {
	return b.metadata
}

func Bytes(value []byte, m Metadata) BytesValue {
	return &bytesValue{
		value:         value,
		BaseAttribute: BaseAttribute{metadata: m},
	}
}

func BytesDefault(value []byte, m Metadata) BytesValue {
	b := Bytes(value, m)
	b.(*bytesValue).BaseAttribute.metadata.isDefault = true
	return b
}

func BytesExplicit(value []byte, m Metadata) BytesValue {
	b := Bytes(value, m)
	b.(*bytesValue).BaseAttribute.metadata.isExplicit = true
	return b
}

func BytesUnresolvable(m Metadata) BytesValue {
	b := Bytes(nil, m)
	b.(*bytesValue).BaseAttribute.metadata.isUnresolvable = true
	return b
}

func (s *bytesValue) ToRego() interface{} {
	return map[string]interface{}{
		"filepath":  s.metadata.Range().GetFilename(),
		"startline": s.metadata.Range().GetStartLine(),
		"endline":   s.metadata.Range().GetEndLine(),
		"managed":   s.metadata.isManaged,
		"explicit":  s.metadata.isExplicit,
		"value":     string(s.Value()),
	}
}
