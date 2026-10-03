package types

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"time"
)

type TimeValue struct {
	BaseValue[RFC3339Time]
}

type RFC3339Time struct {
	time.Time
}

func (t RFC3339Time) MarshalJSONTo(enc *jsontext.Encoder) error {
	return json.MarshalEncode(enc, t.Format(time.RFC3339))
}

func (t *RFC3339Time) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if dec.PeekKind() == jsontext.KindNull {
		t.Time = time.Time{}
		return dec.SkipValue()
	}

	var s string
	if err := json.UnmarshalDecode(dec, &s); err != nil {
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
