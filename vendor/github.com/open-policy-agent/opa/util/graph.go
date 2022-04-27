// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package util

// Traversal defines a basic interface to perform traversals.
type Traversal interface {

	// Edges should return the neighbours of node "u".
	Edges(u T) []T

	// Visited should return true if node "u" has already been visited in this
	// traversal. If the same traversal is used multiple times, the state that
	// tracks visited nodes should be reset.
	Visited(u T) bool
}

// Equals should return true if node "u" equals node "v".
type Equals func(u T, v T) bool

// Iter should return true to indicate stop.
type Iter func(u T) bool

// DFS performs a depth first traversal calling f for each node starting from u.
// If f returns true, traversal stops and DFS returns true.
func DFS(t Traversal, f Iter, u T) bool {
	lifo := NewLIFO(u)
	for lifo.Size() > 0 {
		next, _ := lifo.Pop()
		if t.Visited(next) {
			continue
		}
		if f(next) {
			return true
		}
		for _, v := range t.Edges(next) {
			lifo.Push(v)
		}
	}
	return false
}

// BFS performs a breadth first traversal calling f for each node starting from
// u. If f returns true, traversal stops and BFS returns true.
func BFS(t Traversal, f Iter, u T) bool {
	fifo := NewFIFO(u)
	for fifo.Size() > 0 {
		next, _ := fifo.Pop()
		if t.Visited(next) {
			continue
		}
		if f(next) {
			return true
		}
		for _, v := range t.Edges(next) {
			fifo.Push(v)
		}
	}
	return false
}

// DFSPath returns a path from node a to node z found by performing
// a depth first traversal. If no path is found, an empty slice is returned.
func DFSPath(t Traversal, eq Equals, a, z T) []T {
	p := dfsRecursive(t, eq, a, z, []T{})
	for i := len(p)/2 - 1; i >= 0; i-- {
		o := len(p) - i - 1
		p[i], p[o] = p[o], p[i]
	}
	return p
}

func dfsRecursive(t Traversal, eq Equals, u, z T, path []T) []T {
	if t.Visited(u) {
		return path
	}
	for _, v := range t.Edges(u) {
		if eq(v, z) {
			path = append(path, z)
			path = append(path, u)
			return path
		}
		if p := dfsRecursive(t, eq, v, z, path); len(p) > 0 {
			path = append(p, u)
			return path
		}
	}
	return path
}
