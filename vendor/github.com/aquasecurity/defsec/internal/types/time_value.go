package types

import (
	"encoding/json"
	"time"
)

type TimeValue interface {
	metadataProvider
	Value() *time.Time
	LessThan(i time.Time) bool
	GreaterThan(i time.Time) bool
	IsNever() bool
}

type timeValue struct {
	BaseAttribute
	value *time.Time
}

func (v *timeValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func Time(value time.Time, m Metadata) TimeValue {
	return &timeValue{
		value:         &value,
		BaseAttribute: BaseAttribute{metadata: m},
	}
}

func TimeDefault(value time.Time, m Metadata) TimeValue {
	b := Time(value, m)
	b.(*timeValue).BaseAttribute.metadata.isDefault = true
	return b
}

func TimeExplicit(value time.Time, m Metadata) TimeValue {
	b := Time(value, m)
	b.(*timeValue).BaseAttribute.metadata.isExplicit = true
	return b
}

func TimeUnresolvable(m Metadata) TimeValue {
	b := Time(time.Time{}, m)
	b.(*timeValue).BaseAttribute.metadata.isUnresolvable = true
	return b
}

func (b *timeValue) Value() *time.Time {
	return b.value
}

func (b *timeValue) GetRawValue() interface{} {
	return b.value
}

func (b *timeValue) IsNever() bool {
	if b.GetMetadata().isUnresolvable {
		return false
	}
	return b.value.IsZero()
}

func (b *timeValue) LessThan(i time.Time) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	if b.value == nil {
		return false
	}
	return b.value.Before(i)
}

func (b *timeValue) GreaterThan(i time.Time) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	if b.value == nil {
		return false
	}
	return b.value.After(i)
}

func (s *timeValue) ToRego() interface{} {
	return map[string]interface{}{
		"filepath":  s.metadata.Range().GetFilename(),
		"startline": s.metadata.Range().GetStartLine(),
		"endline":   s.metadata.Range().GetEndLine(),
		"managed":   s.metadata.isManaged,
		"explicit":  s.metadata.isExplicit,
		"value":     s.Value().Format(time.RFC3339),
		"fskey":     CreateFSKey(s.metadata.Range().GetFS()),
		"resource":  s.metadata.Reference().String(),
	}
}
