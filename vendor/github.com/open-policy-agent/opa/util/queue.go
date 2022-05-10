// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package util

// LIFO represents a simple LIFO queue.
type LIFO struct {
	top  *queueNode
	size int
}

type queueNode struct {
	v    T
	next *queueNode
}

// NewLIFO returns a new LIFO queue containing elements ts starting with the
// left-most argument at the bottom.
func NewLIFO(ts ...T) *LIFO {
	s := &LIFO{}
	for i := range ts {
		s.Push(ts[i])
	}
	return s
}

// Push adds a new element onto the LIFO.
func (s *LIFO) Push(t T) {
	node := &queueNode{v: t, next: s.top}
	s.top = node
	s.size++
}

// Peek returns the top of the LIFO. If LIFO is empty, returns nil, false.
func (s *LIFO) Peek() (T, bool) {
	if s.top == nil {
		return nil, false
	}
	return s.top.v, true
}

// Pop returns the top of the LIFO and removes it. If LIFO is empty returns
// nil, false.
func (s *LIFO) Pop() (T, bool) {
	if s.top == nil {
		return nil, false
	}
	node := s.top
	s.top = node.next
	s.size--
	return node.v, true
}

// Size returns the size of the LIFO.
func (s *LIFO) Size() int {
	return s.size
}

// FIFO represents a simple FIFO queue.
type FIFO struct {
	front *queueNode
	back  *queueNode
	size  int
}

// NewFIFO returns a new FIFO queue containing elements ts starting with the
// left-most argument at the front.
func NewFIFO(ts ...T) *FIFO {
	s := &FIFO{}
	for i := range ts {
		s.Push(ts[i])
	}
	return s
}

// Push adds a new element onto the LIFO.
func (s *FIFO) Push(t T) {
	node := &queueNode{v: t, next: nil}
	if s.front == nil {
		s.front = node
		s.back = node
	} else {
		s.back.next = node
		s.back = node
	}
	s.size++
}

// Peek returns the top of the LIFO. If LIFO is empty, returns nil, false.
func (s *FIFO) Peek() (T, bool) {
	if s.front == nil {
		return nil, false
	}
	return s.front.v, true
}

// Pop returns the top of the LIFO and removes it. If LIFO is empty returns
// nil, false.
func (s *FIFO) Pop() (T, bool) {
	if s.front == nil {
		return nil, false
	}
	node := s.front
	s.front = node.next
	s.size--
	return node.v, true
}

// Size returns the size of the LIFO.
func (s *FIFO) Size() int {
	return s.size
}
