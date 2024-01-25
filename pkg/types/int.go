package types

import (
	"encoding/json"
)

type IntValue struct {
	BaseAttribute
	value int
}

func (b IntValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"value":             b.value,
		"misconfigmetadata": b.misconfigmetadata,
	})
}

func (b *IntValue) UnmarshalJSON(data []byte) error {
	var keys map[string]interface{}
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["value"] != nil {
		b.value = int(keys["value"].(float64))
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

func Int(value int, m MisconfigMetadata) IntValue {
	return IntValue{
		value:         value,
		BaseAttribute: BaseAttribute{misconfigmetadata: m},
	}
}

func IntFromInt32(value int32, m MisconfigMetadata) IntValue {
	return Int(int(value), m)
}

func IntDefault(value int, m MisconfigMetadata) IntValue {
	b := Int(value, m)
	b.BaseAttribute.misconfigmetadata.isDefault = true
	return b
}

func IntUnresolvable(m MisconfigMetadata) IntValue {
	b := Int(0, m)
	b.BaseAttribute.misconfigmetadata.isUnresolvable = true
	return b
}

func IntExplicit(value int, m MisconfigMetadata) IntValue {
	b := Int(value, m)
	b.BaseAttribute.misconfigmetadata.isExplicit = true
	return b
}

func (b IntValue) GetMetadata() MisconfigMetadata {
	return b.misconfigmetadata
}

func (b IntValue) Value() int {
	return b.value
}

func (b IntValue) GetRawValue() interface{} {
	return b.value
}

func (b IntValue) NotEqualTo(i int) bool {
	if b.misconfigmetadata.isUnresolvable {
		return false
	}
	return b.value != i
}

func (b IntValue) EqualTo(i int) bool {
	if b.misconfigmetadata.isUnresolvable {
		return false
	}
	return b.value == i
}

func (b IntValue) LessThan(i int) bool {
	if b.misconfigmetadata.isUnresolvable {
		return false
	}
	return b.value < i
}

func (b IntValue) GreaterThan(i int) bool {
	if b.misconfigmetadata.isUnresolvable {
		return false
	}
	return b.value > i
}

func (s IntValue) ToRego() interface{} {
	m := s.misconfigmetadata.ToRego().(map[string]interface{})
	m["value"] = s.Value()
	return m
}
