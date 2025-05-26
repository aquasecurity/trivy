package types

import (
	"encoding/json"
	"strings"
)

func String(str string, m Metadata) StringValue {
	return StringValue{
		value:         str,
		BaseAttribute: BaseAttribute{metadata: m},
	}
}

func StringDefault(value string, m Metadata) StringValue {
	b := String(value, m)
	b.BaseAttribute.metadata.isDefault = true
	return b
}

func StringUnresolvable(m Metadata) StringValue {
	b := String("", m)
	b.BaseAttribute.metadata.isUnresolvable = true
	return b
}

func StringExplicit(value string, m Metadata) StringValue {
	b := String(value, m)
	b.BaseAttribute.metadata.isExplicit = true
	return b
}

func StringTest(value string) StringValue {
	return String(value, NewTestMetadata())
}

type StringValueList []StringValue

type StringValue struct {
	BaseAttribute
	value string
}

func (l StringValueList) AsStrings() (output []string) {
	for _, item := range l {
		output = append(output, item.Value())
	}
	return output
}

func (s StringValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"value":    s.value,
		"metadata": s.metadata,
	})
}

func (s *StringValue) UnmarshalJSON(data []byte) error {
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["value"] != nil {
		s.value = keys["value"].(string)
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
		s.metadata = m
	}
	return nil
}

func (s StringValue) ToRego() any {
	m := s.metadata.ToRego().(map[string]any)
	m["value"] = s.Value()
	return m
}

func (s StringValue) IsOneOf(values ...string) bool {
	if s.metadata.isUnresolvable {
		return false
	}
	for _, value := range values {
		if value == s.value {
			return true
		}
	}
	return false
}

func (s StringValue) GetMetadata() Metadata {
	return s.metadata
}

func (s StringValue) Value() string {
	return s.value
}

func (s StringValue) GetRawValue() any {
	return s.value
}

func (s StringValue) IsEmpty() bool {
	if s.metadata.isUnresolvable {
		return false
	}
	return s.value == ""
}

func (s StringValue) IsNotEmpty() bool {
	if s.metadata.isUnresolvable {
		return false
	}
	return s.value != ""
}

func (s StringValue) EqualTo(value string) bool {
	if s.metadata.isUnresolvable {
		return false
	}

	return s.value == value
}

func (s StringValue) NotEqualTo(value string) bool {
	if s.metadata.isUnresolvable {
		return false
	}

	return s.value != value
}

func (s StringValue) StartsWith(prefix string) bool {
	if s.metadata.isUnresolvable {
		return false
	}

	return strings.HasPrefix(s.value, prefix)
}

func (s StringValue) EndsWith(suffix string) bool {
	if s.metadata.isUnresolvable {
		return false
	}
	return strings.HasSuffix(s.value, suffix)
}

func (s StringValue) Contains(value string) bool {
	if s.metadata.isUnresolvable {
		return false
	}
	return strings.Contains(s.value, value)
}
