// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package instruction

import (
	"github.com/open-policy-agent/opa/internal/wasm/opcode"
	"github.com/open-policy-agent/opa/internal/wasm/types"
)

// !!! If you find yourself adding support for more control
//     instructions (br_table, if, ...), please adapt the
//     `withControlInstr` functions of
//     `compiler/wasm/optimizations.go`

// Unreachable represents a WASM unreachable instruction.
type Unreachable struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (Unreachable) Op() opcode.Opcode {
	return opcode.Unreachable
}

// Nop represents a WASM no-op instruction.
type Nop struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (Nop) Op() opcode.Opcode {
	return opcode.Nop
}

// Block represents a WASM block instruction.
type Block struct {
	NoImmediateArgs
	Type   *types.ValueType
	Instrs []Instruction
}

// Op returns the opcode of the instruction
func (Block) Op() opcode.Opcode {
	return opcode.Block
}

// BlockType returns the type of the block's return value.
func (i Block) BlockType() *types.ValueType {
	return i.Type
}

// Instructions returns the instructions contained in the block.
func (i Block) Instructions() []Instruction {
	return i.Instrs
}

// If represents a WASM if instruction.
// NOTE(sr): we only use if with one branch so far!
type If struct {
	NoImmediateArgs
	Type   *types.ValueType
	Instrs []Instruction
}

// Op returns the opcode of the instruction.
func (If) Op() opcode.Opcode {
	return opcode.If
}

// BlockType returns the type of the if's THEN branch.
func (i If) BlockType() *types.ValueType {
	return i.Type
}

// Instructions represents the instructions contained in the if's THEN branch.
func (i If) Instructions() []Instruction {
	return i.Instrs
}

// Loop represents a WASM loop instruction.
type Loop struct {
	NoImmediateArgs
	Type   *types.ValueType
	Instrs []Instruction
}

// Op returns the opcode of the instruction.
func (Loop) Op() opcode.Opcode {
	return opcode.Loop
}

// BlockType returns the type of the loop's return value.
func (i Loop) BlockType() *types.ValueType {
	return i.Type
}

// Instructions represents the instructions contained in the loop.
func (i Loop) Instructions() []Instruction {
	return i.Instrs
}

// Br represents a WASM br instruction.
type Br struct {
	Index uint32
}

// Op returns the opcode of the instruction.
func (Br) Op() opcode.Opcode {
	return opcode.Br
}

// ImmediateArgs returns the block index to break to.
func (i Br) ImmediateArgs() []interface{} {
	return []interface{}{i.Index}
}

// BrIf represents a WASM br_if instruction.
type BrIf struct {
	Index uint32
}

// Op returns the opcode of the instruction.
func (BrIf) Op() opcode.Opcode {
	return opcode.BrIf
}

// ImmediateArgs returns the block index to break to.
func (i BrIf) ImmediateArgs() []interface{} {
	return []interface{}{i.Index}
}

// Call represents a WASM call instruction.
type Call struct {
	Index uint32
}

// Op returns the opcode of the instruction.
func (Call) Op() opcode.Opcode {
	return opcode.Call
}

// ImmediateArgs returns the function index.
func (i Call) ImmediateArgs() []interface{} {
	return []interface{}{i.Index}
}

// CallIndirect represents a WASM call_indirect instruction.
type CallIndirect struct {
	Index    uint32 // type index
	Reserved byte   // zero for now
}

// Op returns the opcode of the instruction.
func (CallIndirect) Op() opcode.Opcode {
	return opcode.CallIndirect
}

// ImmediateArgs returns the function index.
func (i CallIndirect) ImmediateArgs() []interface{} {
	return []interface{}{i.Index, i.Reserved}
}

// Return represents a WASM return instruction.
type Return struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (Return) Op() opcode.Opcode {
	return opcode.Return
}

// End represents the special WASM end instruction.
type End struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (End) Op() opcode.Opcode {
	return opcode.End
}
