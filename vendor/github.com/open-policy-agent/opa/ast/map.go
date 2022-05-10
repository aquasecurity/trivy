// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"encoding/json"

	"github.com/open-policy-agent/opa/util"
)

// ValueMap represents a key/value map between AST term values. Any type of term
// can be used as a key in the map.
type ValueMap struct {
	hashMap *util.HashMap
}

// NewValueMap returns a new ValueMap.
func NewValueMap() *ValueMap {
	vs := &ValueMap{
		hashMap: util.NewHashMap(valueEq, valueHash),
	}
	return vs
}

// MarshalJSON provides a custom marshaller for the ValueMap which
// will include the key, value, and value type.
func (vs *ValueMap) MarshalJSON() ([]byte, error) {
	var tmp []map[string]interface{}
	vs.Iter(func(k Value, v Value) bool {
		tmp = append(tmp, map[string]interface{}{
			"name":  k.String(),
			"type":  TypeName(v),
			"value": v,
		})
		return false
	})
	return json.Marshal(tmp)
}

// Copy returns a shallow copy of the ValueMap.
func (vs *ValueMap) Copy() *ValueMap {
	if vs == nil {
		return nil
	}
	cpy := NewValueMap()
	cpy.hashMap = vs.hashMap.Copy()
	return cpy
}

// Equal returns true if this ValueMap equals the other.
func (vs *ValueMap) Equal(other *ValueMap) bool {
	if vs == nil {
		return other == nil || other.Len() == 0
	}
	if other == nil {
		return vs == nil || vs.Len() == 0
	}
	return vs.hashMap.Equal(other.hashMap)
}

// Len returns the number of elements in the map.
func (vs *ValueMap) Len() int {
	if vs == nil {
		return 0
	}
	return vs.hashMap.Len()
}

// Get returns the value in the map for k.
func (vs *ValueMap) Get(k Value) Value {
	if vs != nil {
		if v, ok := vs.hashMap.Get(k); ok {
			return v.(Value)
		}
	}
	return nil
}

// Hash returns a hash code for this ValueMap.
func (vs *ValueMap) Hash() int {
	if vs == nil {
		return 0
	}
	return vs.hashMap.Hash()
}

// Iter calls the iter function for each key/value pair in the map. If the iter
// function returns true, iteration stops.
func (vs *ValueMap) Iter(iter func(Value, Value) bool) bool {
	if vs == nil {
		return false
	}
	return vs.hashMap.Iter(func(kt, vt util.T) bool {
		k := kt.(Value)
		v := vt.(Value)
		return iter(k, v)
	})
}

// Put inserts a key k into the map with value v.
func (vs *ValueMap) Put(k, v Value) {
	if vs == nil {
		panic("put on nil value map")
	}
	vs.hashMap.Put(k, v)
}

// Delete removes a key k from the map.
func (vs *ValueMap) Delete(k Value) {
	if vs == nil {
		return
	}
	vs.hashMap.Delete(k)
}

func (vs *ValueMap) String() string {
	if vs == nil {
		return "{}"
	}
	return vs.hashMap.String()
}

func valueHash(v util.T) int {
	return v.(Value).Hash()
}

func valueEq(a, b util.T) bool {
	av := a.(Value)
	bv := b.(Value)
	return av.Compare(bv) == 0
}
