package types

import (
	"encoding/json"
	"time"
)

type TimeValue struct {
	BaseAttribute
	value time.Time
}

func (b TimeValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"value":             b.value.Format(time.RFC3339),
		"misconfigmetadata": b.misconfigmetadata,
	})
}

func (b *TimeValue) UnmarshalJSON(data []byte) error {
	var keys map[string]interface{}
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["value"] != nil {
		if ti, err := time.Parse(time.RFC3339, keys["value"].(string)); err == nil {
			b.value = ti
		}
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

func Time(value time.Time, m MisconfigMetadata) TimeValue {
	return TimeValue{
		value:         value,
		BaseAttribute: BaseAttribute{misconfigmetadata: m},
	}
}

func TimeDefault(value time.Time, m MisconfigMetadata) TimeValue {
	b := Time(value, m)
	b.BaseAttribute.misconfigmetadata.isDefault = true
	return b
}

func TimeExplicit(value time.Time, m MisconfigMetadata) TimeValue {
	b := Time(value, m)
	b.BaseAttribute.misconfigmetadata.isExplicit = true
	return b
}

func TimeUnresolvable(m MisconfigMetadata) TimeValue {
	b := Time(time.Time{}, m)
	b.BaseAttribute.misconfigmetadata.isUnresolvable = true
	return b
}

func (t TimeValue) Value() time.Time {
	return t.value
}

func (t TimeValue) GetRawValue() interface{} {
	return t.value
}

func (t TimeValue) IsNever() bool {
	if t.GetMetadata().isUnresolvable {
		return false
	}
	return t.value.IsZero()
}

func (t TimeValue) Before(i time.Time) bool {
	if t.misconfigmetadata.isUnresolvable {
		return false
	}
	return t.value.Before(i)
}

func (t TimeValue) After(i time.Time) bool {
	if t.misconfigmetadata.isUnresolvable {
		return false
	}
	return t.value.After(i)
}

func (t TimeValue) ToRego() interface{} {
	m := t.misconfigmetadata.ToRego().(map[string]interface{})
	m["value"] = t.Value().Format(time.RFC3339)
	return m
}
