// Copyright 2019 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package planner

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/internal/ir"
)

type varstack []map[ast.Var]ir.Local

func newVarstack(frames ...map[ast.Var]ir.Local) *varstack {
	vs := &varstack{}
	for _, f := range frames {
		vs.Push(f)
	}
	return vs
}

func (vs varstack) GetOrElse(k ast.Var, orElse func() ir.Local) ir.Local {
	l, ok := vs.Get(k)
	if !ok {
		l = orElse()
		vs.Put(k, l)
	}
	return l
}

func (vs varstack) GetOrEmpty(k ast.Var) ir.Local {
	l, _ := vs.Get(k)
	return l
}

func (vs varstack) Get(k ast.Var) (ir.Local, bool) {
	for i := len(vs) - 1; i >= 0; i-- {
		if l, ok := vs[i][k]; ok {
			return l, true
		}
	}
	return 0, false
}

func (vs varstack) GetOpOrEmpty(k ast.Var) ir.Operand {
	l := vs.GetOrEmpty(k)
	return ir.Operand{Value: l}
}

func (vs varstack) GetOp(k ast.Var) (ir.Operand, bool) {
	l, ok := vs.Get(k)
	if !ok {
		return ir.Operand{}, false
	}
	return ir.Operand{Value: l}, true
}

func (vs varstack) Put(k ast.Var, v ir.Local) {
	vs[len(vs)-1][k] = v
}

func (vs *varstack) Push(frame map[ast.Var]ir.Local) {
	*vs = append(*vs, frame)
}

func (vs *varstack) Pop() map[ast.Var]ir.Local {
	sl := *vs
	last := sl[len(sl)-1]
	*vs = sl[:len(sl)-1]
	return last
}
