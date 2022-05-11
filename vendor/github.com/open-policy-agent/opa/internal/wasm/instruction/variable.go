// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package instruction

import "github.com/open-policy-agent/opa/internal/wasm/opcode"

// GetLocal represents the WASM get_local instruction.
type GetLocal struct {
	Index uint32
}

// Op returns the opcode of the instruction.
func (GetLocal) Op() opcode.Opcode {
	return opcode.GetLocal
}

// ImmediateArgs returns the index of the local variable to push onto the stack.
func (i GetLocal) ImmediateArgs() []interface{} {
	return []interface{}{i.Index}
}

// SetLocal represents the WASM set_local instruction.
type SetLocal struct {
	Index uint32
}

// Op returns the opcode of the instruction.
func (SetLocal) Op() opcode.Opcode {
	return opcode.SetLocal
}

// ImmediateArgs returns the index of the local variable to set with the top of
// the stack.
func (i SetLocal) ImmediateArgs() []interface{} {
	return []interface{}{i.Index}
}

// TeeLocal represents the WASM tee_local instruction.
type TeeLocal struct {
	Index uint32
}

// Op returns the opcode of the instruction.
func (TeeLocal) Op() opcode.Opcode {
	return opcode.TeeLocal
}

// ImmediateArgs returns the index of the local variable to "tee" with the top of
// the stack (like set, but retaining the top of the stack).
func (i TeeLocal) ImmediateArgs() []interface{} {
	return []interface{}{i.Index}
}
