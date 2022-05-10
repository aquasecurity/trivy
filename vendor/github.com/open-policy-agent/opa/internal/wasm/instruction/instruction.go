// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package instruction defines WASM instruction types.
package instruction

import (
	"github.com/open-policy-agent/opa/internal/wasm/opcode"
	"github.com/open-policy-agent/opa/internal/wasm/types"
)

// NoImmediateArgs indicates the instruction has no immediate arguments.
type NoImmediateArgs struct {
}

// ImmediateArgs returns the immedate arguments of an instruction.
func (NoImmediateArgs) ImmediateArgs() []interface{} {
	return nil
}

// Instruction represents a single WASM instruction.
type Instruction interface {
	Op() opcode.Opcode
	ImmediateArgs() []interface{}
}

// StructuredInstruction represents a structured control instruction like br_if.
type StructuredInstruction interface {
	Instruction
	BlockType() *types.ValueType
	Instructions() []Instruction
}
