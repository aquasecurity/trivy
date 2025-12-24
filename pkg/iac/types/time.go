package types

import (
	"encoding/json"
	"time"
)

type TimeValue struct {
	BaseValue[RFC3339Time]
}

type RFC3339Time struct {
	time.Time
}

func (t RFC3339Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Format(time.RFC3339))
}

func (t *RFC3339Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		t.Time = time.Time{}
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	ti, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	t.Time = ti
	return nil
}

func Time(value time.Time, m Metadata) TimeValue {
	return TimeValue{newValue(RFC3339Time{value}, m)}
}

func TimeDefault(value time.Time, m Metadata) TimeValue {
	return TimeValue{defaultValue(RFC3339Time{value}, m)}
}

func TimeExplicit(value time.Time, m Metadata) TimeValue {
	return TimeValue{explicitValue(RFC3339Time{value}, m)}
}

func TimeUnresolvable(m Metadata) TimeValue {
	return TimeValue{unresolvableValue[RFC3339Time](m)}
}

func TimeTest(value time.Time) TimeValue {
	return TimeValue{testValue(RFC3339Time{value})}
}

func (t TimeValue) Value() time.Time {
	return t.value.Time
}

func (t TimeValue) GetRawValue() any {
	return t.value
}

func (t TimeValue) ToRego() any {
	m := t.metadata.ToRego().(map[string]any)
	m["value"] = t.value.Format(time.RFC3339)
	return m
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
