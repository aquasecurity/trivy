// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package instruction

import (
	"github.com/open-policy-agent/opa/internal/wasm/opcode"
)

// I32Const represents the WASM i32.const instruction.
type I32Const struct {
	Value int32
}

// Op returns the opcode of the instruction.
func (I32Const) Op() opcode.Opcode {
	return opcode.I32Const
}

// ImmediateArgs returns the i32 value to push onto the stack.
func (i I32Const) ImmediateArgs() []interface{} {
	return []interface{}{i.Value}
}

// I64Const represents the WASM i64.const instruction.
type I64Const struct {
	Value int64
}

// Op returns the opcode of the instruction.
func (I64Const) Op() opcode.Opcode {
	return opcode.I64Const
}

// ImmediateArgs returns the i64 value to push onto the stack.
func (i I64Const) ImmediateArgs() []interface{} {
	return []interface{}{i.Value}
}

// F32Const represents the WASM f32.const instruction.
type F32Const struct {
	Value int32
}

// Op returns the opcode of the instruction.
func (F32Const) Op() opcode.Opcode {
	return opcode.F32Const
}

// ImmediateArgs returns the f32 value to push onto the stack.
func (i F32Const) ImmediateArgs() []interface{} {
	return []interface{}{i.Value}
}

// F64Const represents the WASM f64.const instruction.
type F64Const struct {
	Value float64
}

// Op returns the opcode of the instruction.
func (F64Const) Op() opcode.Opcode {
	return opcode.F64Const
}

// ImmediateArgs returns the f64 value to push onto the stack.
func (i F64Const) ImmediateArgs() []interface{} {
	return []interface{}{i.Value}
}

// I32Eqz represents the WASM i32.eqz instruction.
type I32Eqz struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (I32Eqz) Op() opcode.Opcode {
	return opcode.I32Eqz
}

// I32Eq represents the WASM i32.eq instruction.
type I32Eq struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (I32Eq) Op() opcode.Opcode {
	return opcode.I32Eq
}

// I32Ne represents the WASM i32.ne instruction.
type I32Ne struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (I32Ne) Op() opcode.Opcode {
	return opcode.I32Ne
}

// I32GtS represents the WASM i32.gt_s instruction.
type I32GtS struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (I32GtS) Op() opcode.Opcode {
	return opcode.I32GtS
}

// I32GeS represents the WASM i32.ge_s instruction.
type I32GeS struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (I32GeS) Op() opcode.Opcode {
	return opcode.I32GeS
}

// I32LtS represents the WASM i32.lt_s instruction.
type I32LtS struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (I32LtS) Op() opcode.Opcode {
	return opcode.I32LtS
}

// I32LeS represents the WASM i32.le_s instruction.
type I32LeS struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (I32LeS) Op() opcode.Opcode {
	return opcode.I32LeS
}

// I32Add represents the WASM i32.add instruction.
type I32Add struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (I32Add) Op() opcode.Opcode {
	return opcode.I32Add
}

// I64Add represents the WASM i64.add instruction.
type I64Add struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (I64Add) Op() opcode.Opcode {
	return opcode.I64Add
}

// F32Add represents the WASM f32.add instruction.
type F32Add struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (F32Add) Op() opcode.Opcode {
	return opcode.F32Add
}

// F64Add represents the WASM f64.add instruction.
type F64Add struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (F64Add) Op() opcode.Opcode {
	return opcode.F64Add
}

// I32Mul represents the WASM i32.mul instruction.
type I32Mul struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (I32Mul) Op() opcode.Opcode {
	return opcode.I32Mul
}

// I32Sub represents the WASM i32.sub instruction.
type I32Sub struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (I32Sub) Op() opcode.Opcode {
	return opcode.I32Sub
}
