package vm

import "errors"

var (
	ErrInvalidSignature = errors.New("invalid signature error")
	ErrUnsupportedType  = errors.New("unsupported type error")
)

type Cache[K comparable, V any] interface {
	// Add stores data in the cache
	Add(key K, value V) (evicted bool)

	// Get returns key's value from the cache
	Get(key K) (value V, ok bool)
}
