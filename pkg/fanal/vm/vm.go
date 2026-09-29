package vm

import (
	"golang.org/x/xerrors"
)

var (
	ErrInvalidSignature = xerrors.New("invalid signature error")
	ErrUnsupportedType  = xerrors.New("unsupported type error")
)

type Cache[K comparable, V any] interface {
	// Add stores data in the cache
	Add(key K, value V) (evicted bool)

	// Get returns key's value from the cache
	Get(key K) (value V, ok bool)
}
