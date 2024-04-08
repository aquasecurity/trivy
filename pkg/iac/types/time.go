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
		"value":    b.value.Format(time.RFC3339),
		"metadata": b.metadata,
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

func Time(value time.Time, m Metadata) TimeValue {
	return TimeValue{
		value:         value,
		BaseAttribute: BaseAttribute{metadata: m},
	}
}

func TimeDefault(value time.Time, m Metadata) TimeValue {
	b := Time(value, m)
	b.BaseAttribute.metadata.isDefault = true
	return b
}

func TimeExplicit(value time.Time, m Metadata) TimeValue {
	b := Time(value, m)
	b.BaseAttribute.metadata.isExplicit = true
	return b
}

func TimeUnresolvable(m Metadata) TimeValue {
	b := Time(time.Time{}, m)
	b.BaseAttribute.metadata.isUnresolvable = true
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
	if t.metadata.isUnresolvable {
		return false
	}
	return t.value.Before(i)
}

func (t TimeValue) After(i time.Time) bool {
	if t.metadata.isUnresolvable {
		return false
	}
	return t.value.After(i)
}

func (t TimeValue) ToRego() interface{} {
	m := t.metadata.ToRego().(map[string]interface{})
	m["value"] = t.Value().Format(time.RFC3339)
	return m
}
