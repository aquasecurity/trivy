// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
)

func builtinTypeName(a ast.Value) (ast.Value, error) {
	switch a.(type) {
	case ast.Null:
		return ast.String("null"), nil
	case ast.Boolean:
		return ast.String("boolean"), nil
	case ast.Number:
		return ast.String("number"), nil
	case ast.String:
		return ast.String("string"), nil
	case *ast.Array:
		return ast.String("array"), nil
	case ast.Object:
		return ast.String("object"), nil
	case ast.Set:
		return ast.String("set"), nil
	}

	return nil, fmt.Errorf("illegal value")
}

func init() {
	RegisterFunctionalBuiltin1(ast.TypeNameBuiltin.Name, builtinTypeName)
}
