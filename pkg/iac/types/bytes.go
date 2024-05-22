package types

import (
	"encoding/json"
)

type BytesValue struct {
	BaseAttribute
	value []byte
}

func (b BytesValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"value":    b.value,
		"metadata": b.metadata,
	})
}

func (b *BytesValue) UnmarshalJSON(data []byte) error {
	var keys map[string]interface{}
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["value"] != nil {
		raw, err := json.Marshal(keys["value"])
		if err != nil {
			return err
		}
		var m []byte
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		b.value = m
	}
	if keys["metadata"] != nil {
		raw, err := json.Marshal(keys["metadata"])
		if err != nil {
			return err
		}
		var m Metadata
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		b.metadata = m
	}
	return nil
}

func (b BytesValue) Value() []byte {
	return b.value
}

func (b BytesValue) GetRawValue() interface{} {
	return b.value
}

func (b BytesValue) Len() int {
	return len(b.value)
}

func (b BytesValue) GetMetadata() Metadata {
	return b.metadata
}

func Bytes(value []byte, m Metadata) BytesValue {
	return BytesValue{
		value:         value,
		BaseAttribute: BaseAttribute{metadata: m},
	}
}

func BytesDefault(value []byte, m Metadata) BytesValue {
	b := Bytes(value, m)
	b.BaseAttribute.metadata.isDefault = true
	return b
}

func BytesExplicit(value []byte, m Metadata) BytesValue {
	b := Bytes(value, m)
	b.BaseAttribute.metadata.isExplicit = true
	return b
}

func BytesUnresolvable(m Metadata) BytesValue {
	b := Bytes(nil, m)
	b.BaseAttribute.metadata.isUnresolvable = true
	return b
}

func (s BytesValue) ToRego() interface{} {
	m := s.metadata.ToRego().(map[string]interface{})
	m["value"] = string(s.Value())
	return m
}
