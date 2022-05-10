package part

import (
	"golang.org/x/xerrors"
)

type Any bool

func NewAny(s string) (Any, error) {
	if s == "*" || s == "x" || s == "X" {
		return true, nil
	}
	return true, xerrors.New("not wildcard")
}

func (s Any) Compare(other Part) int {
	if s {
		return 0
	}
	return -1
}

func (s Any) IsNull() bool {
	return false
}

func (s Any) IsAny() bool {
	return bool(s)
}

func (s Any) IsEmpty() bool {
	return false
}
