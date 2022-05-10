package part

var Infinity = InfinityType{}

type InfinityType struct{}

func (InfinityType) Compare(other Part) int {
	switch other.(type) {
	case InfinityType:
		return 0
	default:
		return 1
	}
}

func (InfinityType) IsNull() bool {
	return false
}

func (InfinityType) IsAny() bool {
	return false
}

func (InfinityType) IsEmpty() bool {
	return false
}

var NegativeInfinity = NegativeInfinityType{}

type NegativeInfinityType struct{}

func (NegativeInfinityType) Compare(other Part) int {
	switch other.(type) {
	case NegativeInfinityType:
		return 0
	default:
		return -1
	}
}

func (NegativeInfinityType) IsNull() bool {
	return false
}

func (NegativeInfinityType) IsAny() bool {
	return false
}

func (NegativeInfinityType) IsEmpty() bool {
	return false
}
