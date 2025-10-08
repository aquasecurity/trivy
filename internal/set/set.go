package set

import "iter"

// Set defines the interface for set operations
type Set[T comparable] interface {
	// Append adds multiple items to the set and returns the new size
	Append(val ...T) int

	// Remove removes an item from the set
	Remove(item T)

	// Contains checks if an item exists in the set
	Contains(item T) bool

	// Size returns the number of items in the set
	Size() int

	// Clear removes all items from the set
	Clear()

	// Clone returns a new set with a copy of all items
	Clone() Set[T]

	// Items returns all items in the set as a slice
	Items() []T

	// Iter returns an iterator over the set
	Iter() iter.Seq[T]

	// Union returns a new set containing all items from both sets
	Union(other Set[T]) Set[T]

	// Intersection returns a new set containing items present in both sets
	Intersection(other Set[T]) Set[T]

	// Difference returns a new set containing items present in this set but not in the other
	Difference(other Set[T]) Set[T]
}
