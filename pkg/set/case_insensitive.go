package set

import (
	"iter"
	"maps"
	"slices"
	"strings"
)

// caseInsensitiveStringSet represents a case-insensitive string set implementation
// It stores strings with case-insensitive comparison while preserving the original casing
// of the first occurrence of each unique string (case-insensitive).
// The map key is the lowercase version, and the value is the original string.
// WARNING: This implementation is not thread-safe
type caseInsensitiveStringSet map[string]string //nolint: gocritic

// NewCaseInsensitive creates a new empty case-insensitive string set with optional initial values
// The first occurrence of each unique string (case-insensitive) will be preserved.
// For example: NewCaseInsensitive("Hello", "HELLO", "world") will contain "Hello" and "world"
func NewCaseInsensitive(values ...string) Set[string] {
	s := make(caseInsensitiveStringSet, len(values))
	s.Append(values...)
	return s
}

// Append adds multiple items to the set and returns the new size
// If an item already exists (case-insensitive), it will not be added again
// and the original casing is preserved
func (s caseInsensitiveStringSet) Append(values ...string) int {
	for _, v := range values {
		key := strings.ToLower(v)
		if _, exists := s[key]; !exists {
			s[key] = v
		}
	}
	return len(s)
}

// Remove removes an item from the set (case-insensitive)
func (s caseInsensitiveStringSet) Remove(item string) {
	delete(s, strings.ToLower(item))
}

// Contains checks if an item exists in the set (case-insensitive)
func (s caseInsensitiveStringSet) Contains(item string) bool {
	_, exists := s[strings.ToLower(item)]
	return exists
}

// Size returns the number of items in the set
func (s caseInsensitiveStringSet) Size() int {
	return len(s)
}

// Clear removes all items from the set
func (s caseInsensitiveStringSet) Clear() {
	clear(s)
}

// Clone returns a new set with a copy of all items
func (s caseInsensitiveStringSet) Clone() Set[string] {
	return maps.Clone(s)
}

// Items returns all items in the set as a slice with their original casing
func (s caseInsensitiveStringSet) Items() []string {
	return slices.Collect(s.Iter())
}

// Iter returns an iterator over the set values with their original casing
func (s caseInsensitiveStringSet) Iter() iter.Seq[string] {
	return maps.Values(s)
}

// Union returns a new case-insensitive set containing all items from both sets
// If the same item (case-insensitive) exists in both sets, the casing from this set is preserved
func (s caseInsensitiveStringSet) Union(other Set[string]) Set[string] {
	result := make(caseInsensitiveStringSet, s.Size()+other.Size())
	maps.Copy(result, s)
	result.Append(other.Items()...)
	return result
}

// Intersection returns a new case-insensitive set containing items present in both sets
// The casing from this set is preserved for matching items
func (s caseInsensitiveStringSet) Intersection(other Set[string]) Set[string] {
	result := make(caseInsensitiveStringSet)
	for _, v := range s {
		if other.Contains(v) {
			result.Append(v)
		}
	}
	return result
}

// Difference returns a new case-insensitive set containing items present in this set but not in the other
// The casing from this set is preserved
func (s caseInsensitiveStringSet) Difference(other Set[string]) Set[string] {
	result := make(caseInsensitiveStringSet)
	for _, v := range s {
		if !other.Contains(v) {
			result.Append(v)
		}
	}
	return result
}
