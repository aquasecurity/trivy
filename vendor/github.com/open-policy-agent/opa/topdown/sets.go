// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

// Deprecated in v0.4.2 in favour of minus/infix "-" operation.
func builtinSetDiff(a, b ast.Value) (ast.Value, error) {

	s1, err := builtins.SetOperand(a, 1)
	if err != nil {
		return nil, err
	}

	s2, err := builtins.SetOperand(b, 2)
	if err != nil {
		return nil, err
	}

	return s1.Diff(s2), nil
}

// builtinSetIntersection returns the intersection of the given input sets
func builtinSetIntersection(a ast.Value) (ast.Value, error) {

	inputSet, err := builtins.SetOperand(a, 1)
	if err != nil {
		return nil, err
	}

	// empty input set
	if inputSet.Len() == 0 {
		return ast.NewSet(), nil
	}

	var result ast.Set

	err = inputSet.Iter(func(x *ast.Term) error {
		n, err := builtins.SetOperand(x.Value, 1)
		if err != nil {
			return err
		}

		if result == nil {
			result = n
		} else {
			result = result.Intersect(n)
		}
		return nil
	})
	return result, err
}

// builtinSetUnion returns the union of the given input sets
func builtinSetUnion(a ast.Value) (ast.Value, error) {

	inputSet, err := builtins.SetOperand(a, 1)
	if err != nil {
		return nil, err
	}

	result := ast.NewSet()

	err = inputSet.Iter(func(x *ast.Term) error {
		n, err := builtins.SetOperand(x.Value, 1)
		if err != nil {
			return err
		}
		result = result.Union(n)
		return nil
	})
	return result, err
}

func init() {
	RegisterFunctionalBuiltin2(ast.SetDiff.Name, builtinSetDiff)
	RegisterFunctionalBuiltin1(ast.Intersection.Name, builtinSetIntersection)
	RegisterFunctionalBuiltin1(ast.Union.Name, builtinSetUnion)
}
