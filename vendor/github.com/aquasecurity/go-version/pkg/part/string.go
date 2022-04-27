package part

import (
	"strings"
)

type String string

func NewString(s string) String {
	return String(s)
}

func (s String) Compare(other Part) int {
	if other == nil {
		return 1
	} else if s == other {
		return 0
	}

	switch o := other.(type) {
	case Uint64:
		return 1
	case String:
		return strings.Compare(string(s), string(o))
	case PreString:
		return strings.Compare(string(s), string(o))
	case Any:
		return 0
	case Empty:
		if o.IsAny() {
			return 0
		}
		return s.Compare(Uint64(0))
	}
	return 0
}

func (s String) IsNull() bool {
	return s == ""
}

func (s String) IsAny() bool {
	return false
}

func (s String) IsEmpty() bool {
	return false
}

// PreString is less than the number
// e.g. a < 1
type PreString string

func NewPreString(s string) PreString {
	return PreString(s)
}

func (s PreString) Compare(other Part) int {
	if other == nil {
		return 1
	} else if s == other {
		return 0
	}

	switch o := other.(type) {
	case Uint64:
		return -1
	case String:
		return strings.Compare(string(s), string(o))
	case PreString:
		return strings.Compare(string(s), string(o))
	case Any:
		return 0
	case Empty:
		if o.IsAny() {
			return 0
		}

		return s.Compare(Uint64(0))
	}
	return 0
}

func (s PreString) IsNull() bool {
	return s == ""
}

func (s PreString) IsAny() bool {
	return false
}

func (s PreString) IsEmpty() bool {
	return false
}
