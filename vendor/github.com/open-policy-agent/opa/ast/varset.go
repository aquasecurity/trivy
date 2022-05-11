// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"fmt"
	"sort"
)

// VarSet represents a set of variables.
type VarSet map[Var]struct{}

// NewVarSet returns a new VarSet containing the specified variables.
func NewVarSet(vs ...Var) VarSet {
	s := VarSet{}
	for _, v := range vs {
		s.Add(v)
	}
	return s
}

// Add updates the set to include the variable "v".
func (s VarSet) Add(v Var) {
	s[v] = struct{}{}
}

// Contains returns true if the set contains the variable "v".
func (s VarSet) Contains(v Var) bool {
	_, ok := s[v]
	return ok
}

// Copy returns a shallow copy of the VarSet.
func (s VarSet) Copy() VarSet {
	cpy := VarSet{}
	for v := range s {
		cpy.Add(v)
	}
	return cpy
}

// Diff returns a VarSet containing variables in s that are not in vs.
func (s VarSet) Diff(vs VarSet) VarSet {
	r := VarSet{}
	for v := range s {
		if !vs.Contains(v) {
			r.Add(v)
		}
	}
	return r
}

// Equal returns true if s contains exactly the same elements as vs.
func (s VarSet) Equal(vs VarSet) bool {
	if len(s.Diff(vs)) > 0 {
		return false
	}
	return len(vs.Diff(s)) == 0
}

// Intersect returns a VarSet containing variables in s that are in vs.
func (s VarSet) Intersect(vs VarSet) VarSet {
	r := VarSet{}
	for v := range s {
		if vs.Contains(v) {
			r.Add(v)
		}
	}
	return r
}

// Sorted returns a sorted slice of vars from s.
func (s VarSet) Sorted() []Var {
	sorted := make([]Var, 0, len(s))
	for v := range s {
		sorted = append(sorted, v)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Compare(sorted[j]) < 0
	})
	return sorted
}

// Update merges the other VarSet into this VarSet.
func (s VarSet) Update(vs VarSet) {
	for v := range vs {
		s.Add(v)
	}
}

func (s VarSet) String() string {
	tmp := []string{}
	for v := range s {
		tmp = append(tmp, string(v))
	}
	sort.Strings(tmp)
	return fmt.Sprintf("%v", tmp)
}
