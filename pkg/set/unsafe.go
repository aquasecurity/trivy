package set

import (
	"iter"
	"maps"
	"slices"
)

// unsafeSet represents a non-thread-safe set implementation
// WARNING: This implementation is not thread-safe
type unsafeSet[T comparable] map[T]struct{} //nolint: gocritic

// New creates a new empty non-thread-safe set with optional initial values
func New[T comparable](values ...T) Set[T] {
	s := make(unsafeSet[T])
	for _, v := range values {
		s[v] = struct{}{}
	}
	return s
}

// Append adds multiple items to the set and returns the new size
func (s unsafeSet[T]) Append(val ...T) int {
	for _, item := range val {
		s[item] = struct{}{}
	}
	return len(s)
}

// Remove removes an item from the set
func (s unsafeSet[T]) Remove(item T) {
	delete(s, item)
}

// Contains checks if an item exists in the set
func (s unsafeSet[T]) Contains(item T) bool {
	_, exists := s[item]
	return exists
}

// Size returns the number of items in the set
func (s unsafeSet[T]) Size() int {
	return len(s)
}

// Clear removes all items from the set
func (s unsafeSet[T]) Clear() {
	for k := range s {
		delete(s, k)
	}
}

// Clone returns a new set with a copy of all items
func (s unsafeSet[T]) Clone() Set[T] {
	return maps.Clone(s)
}

// Items returns all items in the set as a slice
func (s unsafeSet[T]) Items() []T {
	return slices.Collect(s.Iter())
}

// Iter returns an iterator over the set
func (s unsafeSet[T]) Iter() iter.Seq[T] {
	return maps.Keys(s)
}

// Union returns a new set containing all items from both sets
func (s unsafeSet[T]) Union(other Set[T]) Set[T] {
	result := make(unsafeSet[T])
	for k := range s {
		result[k] = struct{}{}
	}
	for _, item := range other.Items() {
		result[item] = struct{}{}
	}
	return result
}

// Intersection returns a new set containing items present in both sets
func (s unsafeSet[T]) Intersection(other Set[T]) Set[T] {
	result := make(unsafeSet[T])
	for k := range s {
		if other.Contains(k) {
			result[k] = struct{}{}
		}
	}
	return result
}

// Difference returns a new set containing items present in this set but not in the other
func (s unsafeSet[T]) Difference(other Set[T]) Set[T] {
	result := make(unsafeSet[T])
	for k := range s {
		if !other.Contains(k) {
			result[k] = struct{}{}
		}
	}
	return result
}
