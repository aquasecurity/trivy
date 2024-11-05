package types

import (
	"encoding/json"
)

type IntValue struct {
	BaseAttribute
	value int
}

func (b IntValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"value":    b.value,
		"metadata": b.metadata,
	})
}

func (b *IntValue) UnmarshalJSON(data []byte) error {
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["value"] != nil {
		b.value = int(keys["value"].(float64))
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

func Int(value int, m Metadata) IntValue {
	return IntValue{
		value:         value,
		BaseAttribute: BaseAttribute{metadata: m},
	}
}

func IntTest(value int) IntValue {
	return Int(value, NewTestMetadata())
}

func IntFromInt32(value int32, m Metadata) IntValue {
	return Int(int(value), m)
}

func IntDefault(value int, m Metadata) IntValue {
	b := Int(value, m)
	b.BaseAttribute.metadata.isDefault = true
	return b
}

func IntUnresolvable(m Metadata) IntValue {
	b := Int(0, m)
	b.BaseAttribute.metadata.isUnresolvable = true
	return b
}

func IntExplicit(value int, m Metadata) IntValue {
	b := Int(value, m)
	b.BaseAttribute.metadata.isExplicit = true
	return b
}

func (b IntValue) GetMetadata() Metadata {
	return b.metadata
}

func (b IntValue) Value() int {
	return b.value
}

func (b IntValue) GetRawValue() any {
	return b.value
}

func (b IntValue) NotEqualTo(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value != i
}

func (b IntValue) EqualTo(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value == i
}

func (b IntValue) LessThan(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value < i
}

func (b IntValue) GreaterThan(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value > i
}

func (s IntValue) ToRego() any {
	m := s.metadata.ToRego().(map[string]any)
	m["value"] = s.Value()
	return m
}
