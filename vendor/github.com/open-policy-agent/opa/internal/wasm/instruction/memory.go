// Copyright 2019 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package instruction

import "github.com/open-policy-agent/opa/internal/wasm/opcode"

// I32Load represents the WASM i32.load instruction.
type I32Load struct {
	Offset int32
	Align  int32 // expressed as a power of two
}

// Op returns the opcode of the instruction.
func (I32Load) Op() opcode.Opcode {
	return opcode.I32Load
}

// ImmediateArgs returns the static offset and alignment operands.
func (i I32Load) ImmediateArgs() []interface{} {
	return []interface{}{i.Align, i.Offset}
}

// I32Store represents the WASM i32.store instruction.
type I32Store struct {
	Offset int32
	Align  int32 // expressed as a power of two
}

// Op returns the opcode of the instruction.
func (I32Store) Op() opcode.Opcode {
	return opcode.I32Store
}

// ImmediateArgs returns the static offset and alignment operands.
func (i I32Store) ImmediateArgs() []interface{} {
	return []interface{}{i.Align, i.Offset}
}
