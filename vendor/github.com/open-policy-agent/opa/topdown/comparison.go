// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import "github.com/open-policy-agent/opa/ast"

type compareFunc func(a, b ast.Value) bool

func compareGreaterThan(a, b ast.Value) bool {
	return ast.Compare(a, b) > 0
}

func compareGreaterThanEq(a, b ast.Value) bool {
	return ast.Compare(a, b) >= 0
}

func compareLessThan(a, b ast.Value) bool {
	return ast.Compare(a, b) < 0
}

func compareLessThanEq(a, b ast.Value) bool {
	return ast.Compare(a, b) <= 0
}

func compareNotEq(a, b ast.Value) bool {
	return ast.Compare(a, b) != 0
}

func compareEq(a, b ast.Value) bool {
	return ast.Compare(a, b) == 0
}

func builtinCompare(cmp compareFunc) FunctionalBuiltin2 {
	return func(a, b ast.Value) (ast.Value, error) {
		return ast.Boolean(cmp(a, b)), nil
	}
}

func init() {
	RegisterFunctionalBuiltin2(ast.GreaterThan.Name, builtinCompare(compareGreaterThan))
	RegisterFunctionalBuiltin2(ast.GreaterThanEq.Name, builtinCompare(compareGreaterThanEq))
	RegisterFunctionalBuiltin2(ast.LessThan.Name, builtinCompare(compareLessThan))
	RegisterFunctionalBuiltin2(ast.LessThanEq.Name, builtinCompare(compareLessThanEq))
	RegisterFunctionalBuiltin2(ast.NotEqual.Name, builtinCompare(compareNotEq))
	RegisterFunctionalBuiltin2(ast.Equal.Name, builtinCompare(compareEq))
}
