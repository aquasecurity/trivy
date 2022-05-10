// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"encoding/json"
	"fmt"
	"math/big"
)

// Compare returns an integer indicating whether two AST values are less than,
// equal to, or greater than each other.
//
// If a is less than b, the return value is negative. If a is greater than b,
// the return value is positive. If a is equal to b, the return value is zero.
//
// Different types are never equal to each other. For comparison purposes, types
// are sorted as follows:
//
// nil < Null < Boolean < Number < String < Var < Ref < Array < Object < Set <
// ArrayComprehension < ObjectComprehension < SetComprehension < Expr < SomeDecl
// < With < Body < Rule < Import < Package < Module.
//
// Arrays and Refs are equal if and only if both a and b have the same length
// and all corresponding elements are equal. If one element is not equal, the
// return value is the same as for the first differing element. If all elements
// are equal but a and b have different lengths, the shorter is considered less
// than the other.
//
// Objects are considered equal if and only if both a and b have the same sorted
// (key, value) pairs and are of the same length. Other comparisons are
// consistent but not defined.
//
// Sets are considered equal if and only if the symmetric difference of a and b
// is empty.
// Other comparisons are consistent but not defined.
func Compare(a, b interface{}) int {

	if t, ok := a.(*Term); ok {
		if t == nil {
			a = nil
		} else {
			a = t.Value
		}
	}

	if t, ok := b.(*Term); ok {
		if t == nil {
			b = nil
		} else {
			b = t.Value
		}
	}

	if a == nil {
		if b == nil {
			return 0
		}
		return -1
	}
	if b == nil {
		return 1
	}

	sortA := sortOrder(a)
	sortB := sortOrder(b)

	if sortA < sortB {
		return -1
	} else if sortB < sortA {
		return 1
	}

	switch a := a.(type) {
	case Null:
		return 0
	case Boolean:
		b := b.(Boolean)
		if a.Equal(b) {
			return 0
		}
		if !a {
			return -1
		}
		return 1
	case Number:
		if ai, err := json.Number(a).Int64(); err == nil {
			if bi, err := json.Number(b.(Number)).Int64(); err == nil {
				if ai == bi {
					return 0
				}
				if ai < bi {
					return -1
				}
				return 1
			}
		}

		// We use big.Rat for comparing big numbers.
		// It replaces big.Float due to following reason:
		// big.Float comes with a default precision of 64, and setting a
		// larger precision results in more memory being allocated
		// (regardless of the actual number we are parsing with SetString).
		//
		// Note: If we're so close to zero that big.Float says we are zero, do
		// *not* big.Rat).SetString on the original string it'll potentially
		// take very long.
		var bigA, bigB *big.Rat
		fa, ok := new(big.Float).SetString(string(a))
		if !ok {
			panic("illegal value")
		}
		if fa.IsInt() {
			if i, _ := fa.Int64(); i == 0 {
				bigA = new(big.Rat).SetInt64(0)
			}
		}
		if bigA == nil {
			bigA, ok = new(big.Rat).SetString(string(a))
			if !ok {
				panic("illegal value")
			}
		}

		fb, ok := new(big.Float).SetString(string(b.(Number)))
		if !ok {
			panic("illegal value")
		}
		if fb.IsInt() {
			if i, _ := fb.Int64(); i == 0 {
				bigB = new(big.Rat).SetInt64(0)
			}
		}
		if bigB == nil {
			bigB, ok = new(big.Rat).SetString(string(b.(Number)))
			if !ok {
				panic("illegal value")
			}
		}

		return bigA.Cmp(bigB)
	case String:
		b := b.(String)
		if a.Equal(b) {
			return 0
		}
		if a < b {
			return -1
		}
		return 1
	case Var:
		b := b.(Var)
		if a.Equal(b) {
			return 0
		}
		if a < b {
			return -1
		}
		return 1
	case Ref:
		b := b.(Ref)
		return termSliceCompare(a, b)
	case *Array:
		b := b.(*Array)
		return termSliceCompare(a.elems, b.elems)
	case *object:
		b := b.(*object)
		return a.Compare(b)
	case Set:
		b := b.(Set)
		return a.Compare(b)
	case *ArrayComprehension:
		b := b.(*ArrayComprehension)
		if cmp := Compare(a.Term, b.Term); cmp != 0 {
			return cmp
		}
		return Compare(a.Body, b.Body)
	case *ObjectComprehension:
		b := b.(*ObjectComprehension)
		if cmp := Compare(a.Key, b.Key); cmp != 0 {
			return cmp
		}
		if cmp := Compare(a.Value, b.Value); cmp != 0 {
			return cmp
		}
		return Compare(a.Body, b.Body)
	case *SetComprehension:
		b := b.(*SetComprehension)
		if cmp := Compare(a.Term, b.Term); cmp != 0 {
			return cmp
		}
		return Compare(a.Body, b.Body)
	case Call:
		b := b.(Call)
		return termSliceCompare(a, b)
	case *Expr:
		b := b.(*Expr)
		return a.Compare(b)
	case *SomeDecl:
		b := b.(*SomeDecl)
		return a.Compare(b)
	case *Every:
		b := b.(*Every)
		return a.Compare(b)
	case *With:
		b := b.(*With)
		return a.Compare(b)
	case Body:
		b := b.(Body)
		return a.Compare(b)
	case *Head:
		b := b.(*Head)
		return a.Compare(b)
	case *Rule:
		b := b.(*Rule)
		return a.Compare(b)
	case Args:
		b := b.(Args)
		return termSliceCompare(a, b)
	case *Import:
		b := b.(*Import)
		return a.Compare(b)
	case *Package:
		b := b.(*Package)
		return a.Compare(b)
	case *Annotations:
		b := b.(*Annotations)
		return a.Compare(b)
	case *Module:
		b := b.(*Module)
		return a.Compare(b)
	}
	panic(fmt.Sprintf("illegal value: %T", a))
}

type termSlice []*Term

func (s termSlice) Less(i, j int) bool { return Compare(s[i].Value, s[j].Value) < 0 }
func (s termSlice) Swap(i, j int)      { x := s[i]; s[i] = s[j]; s[j] = x }
func (s termSlice) Len() int           { return len(s) }

func sortOrder(x interface{}) int {
	switch x.(type) {
	case Null:
		return 0
	case Boolean:
		return 1
	case Number:
		return 2
	case String:
		return 3
	case Var:
		return 4
	case Ref:
		return 5
	case *Array:
		return 6
	case Object:
		return 7
	case Set:
		return 8
	case *ArrayComprehension:
		return 9
	case *ObjectComprehension:
		return 10
	case *SetComprehension:
		return 11
	case Call:
		return 12
	case Args:
		return 13
	case *Expr:
		return 100
	case *SomeDecl:
		return 101
	case *Every:
		return 102
	case *With:
		return 110
	case *Head:
		return 120
	case Body:
		return 200
	case *Rule:
		return 1000
	case *Import:
		return 1001
	case *Package:
		return 1002
	case *Annotations:
		return 1003
	case *Module:
		return 10000
	}
	panic(fmt.Sprintf("illegal value: %T", x))
}

func importsCompare(a, b []*Import) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if cmp := a[i].Compare(b[i]); cmp != 0 {
			return cmp
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(b) < len(a) {
		return 1
	}
	return 0
}

func annotationsCompare(a, b []*Annotations) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if cmp := a[i].Compare(b[i]); cmp != 0 {
			return cmp
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(b) < len(a) {
		return 1
	}
	return 0
}

func rulesCompare(a, b []*Rule) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if cmp := a[i].Compare(b[i]); cmp != 0 {
			return cmp
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(b) < len(a) {
		return 1
	}
	return 0
}

func termSliceCompare(a, b []*Term) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if cmp := Compare(a[i], b[i]); cmp != 0 {
			return cmp
		}
	}
	if len(a) < len(b) {
		return -1
	} else if len(b) < len(a) {
		return 1
	}
	return 0
}

func withSliceCompare(a, b []*With) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if cmp := Compare(a[i], b[i]); cmp != 0 {
			return cmp
		}
	}
	if len(a) < len(b) {
		return -1
	} else if len(b) < len(a) {
		return 1
	}
	return 0
}
