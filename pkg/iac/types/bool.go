package types

import (
	"encoding/json"
	"strings"

	"github.com/zclconf/go-cty/cty"
)

type BoolValue struct {
	BaseAttribute
	value bool
}

func (b BoolValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"value":    b.value,
		"metadata": b.metadata,
	})
}

func (b *BoolValue) UnmarshalJSON(data []byte) error {
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["value"] != nil {
		b.value = keys["value"].(bool)
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

func Bool(value bool, metadata Metadata) BoolValue {
	return BoolValue{
		value:         value,
		BaseAttribute: BaseAttribute{metadata: metadata},
	}
}

func BoolTest(value bool) BoolValue {
	return Bool(value, NewTestMetadata())
}

func BoolDefault(value bool, metadata Metadata) BoolValue {
	b := Bool(value, metadata)
	b.BaseAttribute.metadata.isDefault = true
	return b
}

func BoolUnresolvable(m Metadata) BoolValue {
	b := Bool(false, m)
	b.BaseAttribute.metadata.isUnresolvable = true
	return b
}

func BoolExplicit(value bool, metadata Metadata) BoolValue {
	b := Bool(value, metadata)
	b.BaseAttribute.metadata.isExplicit = true
	return b
}

func (b BoolValue) Value() bool {
	return b.value
}

func (b BoolValue) GetRawValue() any {
	return b.value
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
	return BoolValue{
		BaseAttribute: b.BaseAttribute,
		value:         !b.value,
	}
}

func (b BoolValue) ToRego() any {
	m := b.metadata.ToRego().(map[string]any)
	m["value"] = b.Value()
	return m
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
