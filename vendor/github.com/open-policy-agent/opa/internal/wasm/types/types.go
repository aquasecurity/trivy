// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package types defines the WASM value type constants.
package types

// ValueType represents an intrinsic value in WASM.
type ValueType int

// Defines the intrinsic value types.
const (
	I32 ValueType = iota
	I64
	F32
	F64
)

func (tpe ValueType) String() string {
	if tpe == I32 {
		return "i32"
	} else if tpe == I64 {
		return "i64"
	} else if tpe == F32 {
		return "f32"
	}
	return "f64"
}

// ElementType defines the type of table elements.
type ElementType int

const (
	// Anyfunc is the union of all table types.
	Anyfunc ElementType = iota
)
