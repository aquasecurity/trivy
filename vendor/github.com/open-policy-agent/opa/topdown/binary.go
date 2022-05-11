// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

func builtinBinaryAnd(a ast.Value, b ast.Value) (ast.Value, error) {

	s1, err := builtins.SetOperand(a, 1)
	if err != nil {
		return nil, err
	}

	s2, err := builtins.SetOperand(b, 2)
	if err != nil {
		return nil, err
	}

	return s1.Intersect(s2), nil
}

func builtinBinaryOr(a ast.Value, b ast.Value) (ast.Value, error) {

	s1, err := builtins.SetOperand(a, 1)
	if err != nil {
		return nil, err
	}

	s2, err := builtins.SetOperand(b, 2)
	if err != nil {
		return nil, err
	}

	return s1.Union(s2), nil
}

func init() {
	RegisterFunctionalBuiltin2(ast.And.Name, builtinBinaryAnd)
	RegisterFunctionalBuiltin2(ast.Or.Name, builtinBinaryOr)
}
