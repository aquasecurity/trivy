package part

type Empty struct {
	any bool
}

func NewEmpty(any bool) Empty {
	return Empty{any: any}
}

func (s Empty) Compare(other Part) int {
	if s.IsAny() {
		return 0
	}
	return Uint64(0).Compare(other)
}

func (s Empty) IsNull() bool {
	return false
}

func (s Empty) IsAny() bool {
	return s.any
}

func (s Empty) IsEmpty() bool {
	return true
}
