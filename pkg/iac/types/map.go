package types

type MapValue struct {
	BaseValue[map[string]string]
}

func Map(value map[string]string, m Metadata) MapValue {
	return MapValue{newValue(value, m)}
}

func MapDefault(value map[string]string, m Metadata) MapValue {
	return MapValue{defaultValue(value, m)}
}

func MapExplicit(value map[string]string, m Metadata) MapValue {
	return MapValue{explicitValue(value, m)}
}

func (b MapValue) Len() int {
	return len(b.value)
}

func (b MapValue) HasKey(key string) bool {
	if b.value == nil {
		return false
	}
	_, ok := b.value[key]
	return ok
}
