package part

import (
	"strconv"
)

const Zero = Uint64(0)

type Uint64 uint64

func NewUint64(s string) (Uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return Uint64(n), nil
}

func (s Uint64) Compare(other Part) int {
	if other == nil {
		return 1
	} else if s == other {
		return 0
	}

	switch o := other.(type) {
	case Uint64:
		if s < o {
			return -1
		}
		return 1
	case String:
		return -1
	case PreString:
		return 1
	case Any:
		return 0
	case Empty:
		if o.IsAny() {
			return 0
		}
		return s.Compare(Uint64(0))
	default:
		panic("unknown type")
	}
}

func (s Uint64) IsNull() bool {
	return s == 0
}

func (s Uint64) IsAny() bool {
	return false
}

func (s Uint64) IsEmpty() bool {
	return false
}
