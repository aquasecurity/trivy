// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"github.com/open-policy-agent/opa/ast"
)

func builtinIsNumber(a ast.Value) (ast.Value, error) {
	switch a.(type) {
	case ast.Number:
		return ast.Boolean(true), nil
	default:
		return nil, BuiltinEmpty{}
	}
}

func builtinIsString(a ast.Value) (ast.Value, error) {
	switch a.(type) {
	case ast.String:
		return ast.Boolean(true), nil
	default:
		return nil, BuiltinEmpty{}
	}
}

func builtinIsBoolean(a ast.Value) (ast.Value, error) {
	switch a.(type) {
	case ast.Boolean:
		return ast.Boolean(true), nil
	default:
		return nil, BuiltinEmpty{}
	}
}

func builtinIsArray(a ast.Value) (ast.Value, error) {
	switch a.(type) {
	case *ast.Array:
		return ast.Boolean(true), nil
	default:
		return nil, BuiltinEmpty{}
	}
}

func builtinIsSet(a ast.Value) (ast.Value, error) {
	switch a.(type) {
	case ast.Set:
		return ast.Boolean(true), nil
	default:
		return nil, BuiltinEmpty{}
	}
}

func builtinIsObject(a ast.Value) (ast.Value, error) {
	switch a.(type) {
	case ast.Object:
		return ast.Boolean(true), nil
	default:
		return nil, BuiltinEmpty{}
	}
}

func builtinIsNull(a ast.Value) (ast.Value, error) {
	switch a.(type) {
	case ast.Null:
		return ast.Boolean(true), nil
	default:
		return nil, BuiltinEmpty{}
	}
}

func init() {
	RegisterFunctionalBuiltin1(ast.IsNumber.Name, builtinIsNumber)
	RegisterFunctionalBuiltin1(ast.IsString.Name, builtinIsString)
	RegisterFunctionalBuiltin1(ast.IsBoolean.Name, builtinIsBoolean)
	RegisterFunctionalBuiltin1(ast.IsArray.Name, builtinIsArray)
	RegisterFunctionalBuiltin1(ast.IsSet.Name, builtinIsSet)
	RegisterFunctionalBuiltin1(ast.IsObject.Name, builtinIsObject)
	RegisterFunctionalBuiltin1(ast.IsNull.Name, builtinIsNull)
}
