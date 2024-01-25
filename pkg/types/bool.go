package types

import (
	"encoding/json"
)

type BoolValue struct {
	BaseAttribute
	value bool
}

func (b BoolValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"value":             b.value,
		"misconfigmetadata": b.misconfigmetadata,
	})
}

func (b *BoolValue) UnmarshalJSON(data []byte) error {
	var keys map[string]interface{}
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["value"] != nil {
		b.value = keys["value"].(bool)
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

func Bool(value bool, misconfigmetadata MisconfigMetadata) BoolValue {
	return BoolValue{
		value:         value,
		BaseAttribute: BaseAttribute{misconfigmetadata: misconfigmetadata},
	}
}

func BoolDefault(value bool, misconfigmetadata MisconfigMetadata) BoolValue {
	b := Bool(value, misconfigmetadata)
	b.BaseAttribute.misconfigmetadata.isDefault = true
	return b
}

func BoolUnresolvable(m MisconfigMetadata) BoolValue {
	b := Bool(false, m)
	b.BaseAttribute.misconfigmetadata.isUnresolvable = true
	return b
}

func BoolExplicit(value bool, misconfigmetadata MisconfigMetadata) BoolValue {
	b := Bool(value, misconfigmetadata)
	b.BaseAttribute.misconfigmetadata.isExplicit = true
	return b
}

func (b BoolValue) Value() bool {
	return b.value
}

func (b BoolValue) GetRawValue() interface{} {
	return b.value
}

func (b BoolValue) IsTrue() bool {
	if b.misconfigmetadata.isUnresolvable {
		return false
	}
	return b.Value()
}

func (b BoolValue) IsFalse() bool {
	if b.misconfigmetadata.isUnresolvable {
		return false
	}
	return !b.Value()
}

func (s BoolValue) ToRego() interface{} {
	m := s.misconfigmetadata.ToRego().(map[string]interface{})
	m["value"] = s.Value()
	return m
}
