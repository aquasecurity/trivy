package types

import (
	"slices"
	"strings"
)

type StringValue struct {
	BaseValue[string]
}

func String(value string, m Metadata) StringValue {
	return StringValue{newValue(value, m)}
}

func StringDefault(value string, m Metadata) StringValue {
	return StringValue{defaultValue(value, m)}
}

func StringUnresolvable(m Metadata) StringValue {
	return StringValue{unresolvableValue[string](m)}
}

func StringExplicit(value string, m Metadata) StringValue {
	return StringValue{explicitValue(value, m)}
}

func StringTest(value string) StringValue {
	return String(value, NewTestMetadata())
}

func (s StringValue) IsOneOf(values ...string) bool {
	if s.metadata.isUnresolvable {
		return false
	}
	return slices.Contains(values, s.value)
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

type StringValueList []StringValue

func (l StringValueList) AsStrings() (output []string) {
	for _, item := range l {
		output = append(output, item.Value())
	}
	return output
}
