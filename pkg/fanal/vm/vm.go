package vm

import (
	"golang.org/x/xerrors"
)

var (
	ErrInvalidSignature = xerrors.New("invalid signature error")
	ErrUnsupportedType  = xerrors.New("unsupported type error")
)

type Cache interface {
	// Add stores data in the cache
	Add(key, value interface{}) bool

	// Get returns key's value from the cache
	Get(key interface{}) (value interface{}, ok bool)
}
