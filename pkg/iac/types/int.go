package types

type IntValue struct {
	BaseValue[int]
}

func Int(value int, m Metadata) IntValue {
	return IntValue{newValue(value, m)}
}

func IntDefault(value int, m Metadata) IntValue {
	return IntValue{defaultValue(value, m)}
}

func IntUnresolvable(m Metadata) IntValue {
	return IntValue{unresolvableValue[int](m)}
}

func IntExplicit(value int, m Metadata) IntValue {
	return IntValue{newValue(value, m)}
}

func IntTest(value int) IntValue {
	return IntValue{testValue(value)}
}

func (b IntValue) EqualTo(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value == i
}

func (b IntValue) LessThan(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value < i
}

func (b IntValue) GreaterThan(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value > i
}
