package types

import (
	"encoding/json"
	"strings"
)

type StringEqualityOption int

const (
	IgnoreCase StringEqualityOption = iota
	IsPallindrome
	IgnoreWhitespace
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

type stringCheckFunc func(string, string) bool

func (b StringValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"value":    b.value,
		"metadata": b.metadata,
	})
}

func (b *StringValue) UnmarshalJSON(data []byte) error {
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["value"] != nil {
		b.value = keys["value"].(string)
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

func (b StringValue) GetRawValue() any {
	return b.value
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

func (s StringValue) EqualTo(value string, equalityOptions ...StringEqualityOption) bool {
	if s.metadata.isUnresolvable {
		return false
	}

	return s.executePredicate(value, func(a, b string) bool { return a == b }, equalityOptions...)
}

func (s StringValue) NotEqualTo(value string, equalityOptions ...StringEqualityOption) bool {
	if s.metadata.isUnresolvable {
		return false
	}

	return !s.EqualTo(value, equalityOptions...)
}

func (s StringValue) StartsWith(prefix string, equalityOptions ...StringEqualityOption) bool {
	if s.metadata.isUnresolvable {
		return false
	}

	return s.executePredicate(prefix, strings.HasPrefix, equalityOptions...)
}

func (s StringValue) EndsWith(suffix string, equalityOptions ...StringEqualityOption) bool {
	if s.metadata.isUnresolvable {
		return false
	}
	return s.executePredicate(suffix, strings.HasSuffix, equalityOptions...)
}

func (s StringValue) Contains(value string, equalityOptions ...StringEqualityOption) bool {
	if s.metadata.isUnresolvable {
		return false
	}
	return s.executePredicate(value, strings.Contains, equalityOptions...)
}

func (s StringValue) executePredicate(value string, fn stringCheckFunc, equalityOptions ...StringEqualityOption) bool {
	subjectString := s.value
	searchString := value

	for _, eqOpt := range equalityOptions {
		switch eqOpt {
		case IgnoreCase:
			subjectString = strings.ToLower(subjectString)
			searchString = strings.ToLower(searchString)
		case IsPallindrome:
			var result string
			for _, v := range subjectString {
				result = string(v) + result
			}
			subjectString = result
		case IgnoreWhitespace:
			subjectString = strings.ReplaceAll(subjectString, " ", "")
			searchString = strings.ReplaceAll(searchString, " ", "")
		}
	}

	return fn(subjectString, searchString)
}
