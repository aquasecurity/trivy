package part

import (
	"fmt"
	"reflect"
	"strings"
)

type Parts []Part

func NewParts(s string) Parts {
	var parts []Part
	if s == "" {
		return parts
	}

	for _, p := range strings.Split(s, ".") {
		parts = append(parts, NewPart(p))
	}
	return parts
}

func (parts Parts) Normalize() Parts {
	ret := make(Parts, len(parts))
	copy(ret, parts)

	for i := len(ret) - 1; i >= 0; i-- {
		lastItem := ret[i]
		if lastItem.IsNull() {
			ret = ret[:i]
			continue
		}
		break
	}
	return ret
}

func (parts Parts) Padding(size int, padding Part) Parts {
	diff := size - len(parts)
	if diff <= 0 {
		return parts
	}

	padded := parts
	for i := 0; i < diff; i++ {
		padded = append(padded, padding)
	}
	return padded
}

func (parts Parts) Compare(other Part) int {
	if other == nil {
		return 1
	} else if other.IsAny() {
		return 0
	}

	var o Parts
	switch t := other.(type) {
	case InfinityType:
		return -1
	case NegativeInfinityType:
		return 1
	case Parts:
		o = t
	default:
		return -1
	}

	if reflect.DeepEqual(parts, o) {
		return 0
	}

	iter := parts.Zip(o)
	for tuple := iter(); tuple != nil; tuple = iter() {
		var l, r = tuple.Left, tuple.Right
		if l == nil {
			return -1
		}
		if r == nil {
			return 1
		}

		if l.IsAny() || r.IsAny() {
			return 0
		}

		if result := l.Compare(r); result != 0 {
			return result
		}
	}
	return 0
}

func (parts Parts) IsNull() bool {
	return parts.IsAny() || len(parts) == 0
}

func (parts Parts) IsAny() bool {
	for _, p := range parts {
		if p.IsAny() {
			return true
		}
	}
	return false
}

func (parts Parts) IsEmpty() bool {
	return false
}

func (parts Parts) String() string {
	s := make([]string, len(parts))
	for i, p := range parts {
		s[i] = fmt.Sprint(p)
	}
	return strings.Join(s, ".")
}

type ZipTuple struct {
	Left  Part
	Right Part
}

func (parts Parts) Zip(other Parts) func() *ZipTuple {
	i := 0
	return func() *ZipTuple {
		var part1, part2 Part
		if i < len(parts) {
			part1 = parts[i]
		}
		if i < len(other) {
			part2 = other[i]
		}
		if part1 == nil && part2 == nil {
			return nil
		}
		i++
		return &ZipTuple{Left: part1, Right: part2}
	}
}

func Uint64SliceToParts(uint64Parts []Uint64) Parts {
	parts := make(Parts, len(uint64Parts))
	for i, u := range uint64Parts {
		parts[i] = u
	}
	return parts
}
