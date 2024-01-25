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
		"value":             b.value,
		"misconfigmetadata": b.misconfigmetadata,
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
	if keys["misconfigmetadata"] != nil {
		raw, err := json.Marshal(keys["misconfigmetadata"])
		if err != nil {
			return err
		}
		var m MisconfigMetadata
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		b.misconfigmetadata = m
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

func (b BytesValue) GetMetadata() MisconfigMetadata {
	return b.misconfigmetadata
}

func Bytes(value []byte, m MisconfigMetadata) BytesValue {
	return BytesValue{
		value:         value,
		BaseAttribute: BaseAttribute{misconfigmetadata: m},
	}
}

func BytesDefault(value []byte, m MisconfigMetadata) BytesValue {
	b := Bytes(value, m)
	b.BaseAttribute.misconfigmetadata.isDefault = true
	return b
}

func BytesExplicit(value []byte, m MisconfigMetadata) BytesValue {
	b := Bytes(value, m)
	b.BaseAttribute.misconfigmetadata.isExplicit = true
	return b
}

func BytesUnresolvable(m MisconfigMetadata) BytesValue {
	b := Bytes(nil, m)
	b.BaseAttribute.misconfigmetadata.isUnresolvable = true
	return b
}

func (s BytesValue) ToRego() interface{} {
	m := s.misconfigmetadata.ToRego().(map[string]interface{})
	m["value"] = string(s.Value())
	return m
}
