// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package instruction

import (
	"github.com/open-policy-agent/opa/internal/wasm/opcode"
)

// Drop reprsents a WASM drop instruction.
type Drop struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (Drop) Op() opcode.Opcode {
	return opcode.Drop
}

// Select reprsents a WASM select instruction.
type Select struct {
	NoImmediateArgs
}

// Op returns the opcode of the instruction.
func (Select) Op() opcode.Opcode {
	return opcode.Select
}
