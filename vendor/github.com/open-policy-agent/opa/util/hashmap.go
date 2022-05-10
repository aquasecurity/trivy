// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package util

import (
	"fmt"
	"strings"
)

// T is a concise way to refer to T.
type T interface{}

type hashEntry struct {
	k    T
	v    T
	next *hashEntry
}

// HashMap represents a key/value map.
type HashMap struct {
	eq    func(T, T) bool
	hash  func(T) int
	table map[int]*hashEntry
	size  int
}

// NewHashMap returns a new empty HashMap.
func NewHashMap(eq func(T, T) bool, hash func(T) int) *HashMap {
	return &HashMap{
		eq:    eq,
		hash:  hash,
		table: make(map[int]*hashEntry),
		size:  0,
	}
}

// Copy returns a shallow copy of this HashMap.
func (h *HashMap) Copy() *HashMap {
	cpy := NewHashMap(h.eq, h.hash)
	h.Iter(func(k, v T) bool {
		cpy.Put(k, v)
		return false
	})
	return cpy
}

// Equal returns true if this HashMap equals the other HashMap.
// Two hash maps are equal if they contain the same key/value pairs.
func (h *HashMap) Equal(other *HashMap) bool {
	if h.Len() != other.Len() {
		return false
	}
	return !h.Iter(func(k, v T) bool {
		ov, ok := other.Get(k)
		if !ok {
			return true
		}
		return !h.eq(v, ov)
	})
}

// Get returns the value for k.
func (h *HashMap) Get(k T) (T, bool) {
	hash := h.hash(k)
	for entry := h.table[hash]; entry != nil; entry = entry.next {
		if h.eq(entry.k, k) {
			return entry.v, true
		}
	}
	return nil, false
}

// Delete removes the the key k.
func (h *HashMap) Delete(k T) {
	hash := h.hash(k)
	var prev *hashEntry
	for entry := h.table[hash]; entry != nil; entry = entry.next {
		if h.eq(entry.k, k) {
			if prev != nil {
				prev.next = entry.next
			} else {
				h.table[hash] = entry.next
			}
			h.size--
			return
		}
		prev = entry
	}
}

// Hash returns the hash code for this hash map.
func (h *HashMap) Hash() int {
	var hash int
	h.Iter(func(k, v T) bool {
		hash += h.hash(k) + h.hash(v)
		return false
	})
	return hash
}

// Iter invokes the iter function for each element in the HashMap.
// If the iter function returns true, iteration stops and the return value is true.
// If the iter function never returns true, iteration proceeds through all elements
// and the return value is false.
func (h *HashMap) Iter(iter func(T, T) bool) bool {
	for _, entry := range h.table {
		for ; entry != nil; entry = entry.next {
			if iter(entry.k, entry.v) {
				return true
			}
		}
	}
	return false
}

// Len returns the current size of this HashMap.
func (h *HashMap) Len() int {
	return h.size
}

// Put inserts a key/value pair into this HashMap. If the key is already present, the existing
// value is overwritten.
func (h *HashMap) Put(k T, v T) {
	hash := h.hash(k)
	head := h.table[hash]
	for entry := head; entry != nil; entry = entry.next {
		if h.eq(entry.k, k) {
			entry.v = v
			return
		}
	}
	h.table[hash] = &hashEntry{k: k, v: v, next: head}
	h.size++
}

func (h *HashMap) String() string {
	var buf []string
	h.Iter(func(k T, v T) bool {
		buf = append(buf, fmt.Sprintf("%v: %v", k, v))
		return false
	})
	return "{" + strings.Join(buf, ", ") + "}"
}

// Update returns a new HashMap with elements from the other HashMap put into this HashMap.
// If the other HashMap contains elements with the same key as this HashMap, the value
// from the other HashMap overwrites the value from this HashMap.
func (h *HashMap) Update(other *HashMap) *HashMap {
	updated := h.Copy()
	other.Iter(func(k, v T) bool {
		updated.Put(k, v)
		return false
	})
	return updated
}
