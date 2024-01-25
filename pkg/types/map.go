package types

import (
	"encoding/json"
)

type MapValue struct {
	BaseAttribute
	value map[string]string
}

func (b MapValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"value":             b.value,
		"misconfigmetadata": b.misconfigmetadata,
	})
}

func (b *MapValue) UnmarshalJSON(data []byte) error {
	var keys map[string]interface{}
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["value"] != nil {
		var target map[string]string
		raw, err := json.Marshal(keys["value"])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &target); err != nil {
			return err
		}
		b.value = target
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

func Map(value map[string]string, m MisconfigMetadata) MapValue {
	return MapValue{
		value:         value,
		BaseAttribute: BaseAttribute{misconfigmetadata: m},
	}
}

func MapDefault(value map[string]string, m MisconfigMetadata) MapValue {
	b := Map(value, m)
	b.BaseAttribute.misconfigmetadata.isDefault = true
	return b
}

func MapExplicit(value map[string]string, m MisconfigMetadata) MapValue {
	b := Map(value, m)
	b.BaseAttribute.misconfigmetadata.isExplicit = true
	return b
}

func (b MapValue) Value() map[string]string {
	return b.value
}

func (b MapValue) GetRawValue() interface{} {
	return b.value
}

func (b MapValue) Len() int {
	return len(b.value)
}

func (b MapValue) HasKey(key string) bool {
	if b.value == nil {
		return false
	}
	_, ok := b.value[key]
	return ok
}

func (s MapValue) ToRego() interface{} {
	m := s.misconfigmetadata.ToRego().(map[string]interface{})
	m["value"] = s.Value()
	return m
}
