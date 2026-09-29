package types

import (
	"encoding/json"
)

type BaseValue[T any] struct {
	metadata Metadata
	value    T
}

func defaultValue[T any](value T, m Metadata) BaseValue[T] {
	m.isDefault = true
	return newValue(value, m)
}

func unresolvableValue[T any](m Metadata) BaseValue[T] {
	m.isUnresolvable = true
	var zero T
	return newValue(zero, m)
}

func explicitValue[T any](value T, m Metadata) BaseValue[T] {
	m.isExplicit = true
	return newValue(value, m)
}

func testValue[T any](value T) BaseValue[T] {
	return newValue(value, NewTestMetadata())
}

func newValue[T any](val T, metadata Metadata) BaseValue[T] {
	return BaseValue[T]{
		metadata: metadata,
		value:    val,
	}
}

func (v BaseValue[T]) GetMetadata() Metadata {
	return v.metadata
}

func (v BaseValue[T]) Value() T {
	return v.value
}

func (v BaseValue[T]) GetRawValue() any {
	return v.value
}

func (v BaseValue[T]) ToRego() any {
	m := v.metadata.ToRego().(map[string]any)
	m["value"] = v.value
	return m
}

type encodedValue[T any] struct {
	Value    T        `json:"value"`
	Metadata Metadata `json:"metadata"`
}

func (v BaseValue[T]) MarshalJSON() ([]byte, error) {
	ev := encodedValue[T]{
		Value:    v.value,
		Metadata: v.metadata,
	}
	return json.Marshal(ev)
}

func (v *BaseValue[T]) UnmarshalJSON(data []byte) error {
	var ev encodedValue[T]
	if err := json.Unmarshal(data, &ev); err != nil {
		return err
	}

	v.value = ev.Value
	v.metadata = ev.Metadata
	return nil
}
