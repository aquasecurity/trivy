// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package util

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
)

// Compare returns 0 if a equals b, -1 if a is less than b, and 1 if b is than a.
//
// For comparison between values of different types, the following ordering is used:
// nil < bool < float64 < string < []interface{} < map[string]interface{}. Slices and maps
// are compared recursively. If one slice or map is a subset of the other slice or map
// it is considered "less than". Nil is always equal to nil.
//
func Compare(a, b interface{}) int {
	aSortOrder := sortOrder(a)
	bSortOrder := sortOrder(b)
	if aSortOrder < bSortOrder {
		return -1
	} else if bSortOrder < aSortOrder {
		return 1
	}
	switch a := a.(type) {
	case nil:
		return 0
	case bool:
		switch b := b.(type) {
		case bool:
			if a == b {
				return 0
			}
			if !a {
				return -1
			}
			return 1
		}
	case json.Number:
		switch b := b.(type) {
		case json.Number:
			return compareJSONNumber(a, b)
		}
	case string:
		switch b := b.(type) {
		case string:
			if a == b {
				return 0
			} else if a < b {
				return -1
			}
			return 1
		}
	case []interface{}:
		switch b := b.(type) {
		case []interface{}:
			bLen := len(b)
			aLen := len(a)
			minLen := aLen
			if bLen < minLen {
				minLen = bLen
			}
			for i := 0; i < minLen; i++ {
				cmp := Compare(a[i], b[i])
				if cmp != 0 {
					return cmp
				}
			}
			if aLen == bLen {
				return 0
			} else if aLen < bLen {
				return -1
			}
			return 1
		}
	case map[string]interface{}:
		switch b := b.(type) {
		case map[string]interface{}:
			var aKeys []string
			for k := range a {
				aKeys = append(aKeys, k)
			}
			var bKeys []string
			for k := range b {
				bKeys = append(bKeys, k)
			}
			sort.Strings(aKeys)
			sort.Strings(bKeys)
			aLen := len(aKeys)
			bLen := len(bKeys)
			minLen := aLen
			if bLen < minLen {
				minLen = bLen
			}
			for i := 0; i < minLen; i++ {
				if aKeys[i] < bKeys[i] {
					return -1
				} else if bKeys[i] < aKeys[i] {
					return 1
				}
				aVal := a[aKeys[i]]
				bVal := b[bKeys[i]]
				cmp := Compare(aVal, bVal)
				if cmp != 0 {
					return cmp
				}
			}
			if aLen == bLen {
				return 0
			} else if aLen < bLen {
				return -1
			}
			return 1
		}
	}

	panic(fmt.Sprintf("illegal arguments of type %T and type %T", a, b))
}

const (
	nilSort    = iota
	boolSort   = iota
	numberSort = iota
	stringSort = iota
	arraySort  = iota
	objectSort = iota
)

func compareJSONNumber(a, b json.Number) int {
	bigA, ok := new(big.Float).SetString(string(a))
	if !ok {
		panic("illegal value")
	}
	bigB, ok := new(big.Float).SetString(string(b))
	if !ok {
		panic("illegal value")
	}
	return bigA.Cmp(bigB)
}

func sortOrder(v interface{}) int {
	switch v.(type) {
	case nil:
		return nilSort
	case bool:
		return boolSort
	case json.Number:
		return numberSort
	case string:
		return stringSort
	case []interface{}:
		return arraySort
	case map[string]interface{}:
		return objectSort
	}
	panic(fmt.Sprintf("illegal argument of type %T", v))
}
