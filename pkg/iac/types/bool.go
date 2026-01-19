package types

import (
	"strings"

	"github.com/zclconf/go-cty/cty"
)

type BoolValue struct {
	BaseValue[bool]
}

func Bool(value bool, m Metadata) BoolValue {
	return BoolValue{newValue(value, m)}
}

func BoolDefault(value bool, m Metadata) BoolValue {
	return BoolValue{defaultValue(value, m)}
}

func BoolUnresolvable(m Metadata) BoolValue {
	return BoolValue{unresolvableValue[bool](m)}
}

func BoolExplicit(value bool, m Metadata) BoolValue {
	return BoolValue{explicitValue(value, m)}
}

func BoolTest(value bool) BoolValue {
	return BoolValue{testValue(value)}
}

func (b BoolValue) IsTrue() bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.Value()
}

func (b BoolValue) IsFalse() bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return !b.Value()
}

func (b BoolValue) Invert() BoolValue {
	return Bool(!b.value, b.metadata)
}

// BoolFromCtyValue converts a cty.Value to iacTypes.BoolValue.
// Returns the BoolValue and true if conversion to bool succeeded.
func BoolFromCtyValue(val cty.Value, metadata Metadata) (BoolValue, bool) {
	if val.IsNull() || !val.IsKnown() {
		return BoolUnresolvable(metadata), false
	}

	unmarked, _ := val.Unmark()
	v, ok := ctyToBool(unmarked)
	if !ok {
		return BoolUnresolvable(metadata), false
	}

	return BoolExplicit(v, metadata), true
}

func ctyToBool(val cty.Value) (bool, bool) {
	switch val.Type() {
	case cty.Bool:
		return val.True(), true
	case cty.String:
		switch strings.ToLower(val.AsString()) {
		case "true", "yes", "y", "1", "on":
			return true, true
		case "false", "no", "n", "0", "off":
			return false, true
		}
	case cty.Number:
		v, _ := val.AsBigFloat().Int64()
		switch v {
		case 1:
			return true, true
		case 0:
			return false, true
		}
	}

	return false, false
}
