// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"strconv"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

func builtinToNumber(a ast.Value) (ast.Value, error) {
	switch a := a.(type) {
	case ast.Null:
		return ast.Number("0"), nil
	case ast.Boolean:
		if a {
			return ast.Number("1"), nil
		}
		return ast.Number("0"), nil
	case ast.Number:
		return a, nil
	case ast.String:
		_, err := strconv.ParseFloat(string(a), 64)
		if err != nil {
			return nil, err
		}
		return ast.Number(a), nil
	}
	return nil, builtins.NewOperandTypeErr(1, a, "null", "boolean", "number", "string")
}

// Deprecated in v0.13.0.
func builtinToArray(a ast.Value) (ast.Value, error) {
	switch val := a.(type) {
	case *ast.Array:
		return val, nil
	case ast.Set:
		arr := make([]*ast.Term, val.Len())
		i := 0
		val.Foreach(func(term *ast.Term) {
			arr[i] = term
			i++
		})
		return ast.NewArray(arr...), nil
	default:
		return nil, builtins.NewOperandTypeErr(1, a, "array", "set")
	}
}

// Deprecated in v0.13.0.
func builtinToSet(a ast.Value) (ast.Value, error) {
	switch val := a.(type) {
	case *ast.Array:
		s := ast.NewSet()
		val.Foreach(func(v *ast.Term) {
			s.Add(v)
		})
		return s, nil
	case ast.Set:
		return val, nil
	default:
		return nil, builtins.NewOperandTypeErr(1, a, "array", "set")
	}
}

// Deprecated in v0.13.0.
func builtinToString(a ast.Value) (ast.Value, error) {
	switch val := a.(type) {
	case ast.String:
		return val, nil
	default:
		return nil, builtins.NewOperandTypeErr(1, a, "string")
	}
}

// Deprecated in v0.13.0.
func builtinToBoolean(a ast.Value) (ast.Value, error) {
	switch val := a.(type) {
	case ast.Boolean:
		return val, nil
	default:
		return nil, builtins.NewOperandTypeErr(1, a, "boolean")
	}
}

// Deprecated in v0.13.0.
func builtinToNull(a ast.Value) (ast.Value, error) {
	switch val := a.(type) {
	case ast.Null:
		return val, nil
	default:
		return nil, builtins.NewOperandTypeErr(1, a, "null")
	}
}

// Deprecated in v0.13.0.
func builtinToObject(a ast.Value) (ast.Value, error) {
	switch val := a.(type) {
	case ast.Object:
		return val, nil
	default:
		return nil, builtins.NewOperandTypeErr(1, a, "object")
	}
}

func init() {
	RegisterFunctionalBuiltin1(ast.ToNumber.Name, builtinToNumber)
	RegisterFunctionalBuiltin1(ast.CastArray.Name, builtinToArray)
	RegisterFunctionalBuiltin1(ast.CastSet.Name, builtinToSet)
	RegisterFunctionalBuiltin1(ast.CastString.Name, builtinToString)
	RegisterFunctionalBuiltin1(ast.CastBoolean.Name, builtinToBoolean)
	RegisterFunctionalBuiltin1(ast.CastNull.Name, builtinToNull)
	RegisterFunctionalBuiltin1(ast.CastObject.Name, builtinToObject)
}
