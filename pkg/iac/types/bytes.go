package types

type BytesValue struct {
	BaseValue[[]byte]
}

func Bytes(value []byte, m Metadata) BytesValue {
	return BytesValue{newValue(value, m)}
}

func BytesDefault(value []byte, m Metadata) BytesValue {
	return BytesValue{defaultValue(value, m)}
}

func BytesExplicit(value []byte, m Metadata) BytesValue {
	return BytesValue{explicitValue(value, m)}
}

func BytesUnresolvable(m Metadata) BytesValue {
	return BytesValue{unresolvableValue[[]byte](m)}
}

func BytesTest(value []byte) BytesValue {
	return BytesValue{testValue(value)}
}

func (v BytesValue) ToRego() any {
	m := v.metadata.ToRego().(map[string]any)
	m["value"] = string(v.value)
	return m
}

func (v BytesValue) Len() int {
	return len(v.value)
}
