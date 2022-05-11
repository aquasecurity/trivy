// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/internal/semver"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

func builtinSemVerCompare(bctx BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	versionStringA, err := builtins.StringOperand(args[0].Value, 1)
	if err != nil {
		return err
	}

	versionStringB, err := builtins.StringOperand(args[1].Value, 2)
	if err != nil {
		return err
	}

	versionA, err := semver.NewVersion(string(versionStringA))
	if err != nil {
		return fmt.Errorf("operand 1: string %s is not a valid SemVer", versionStringA)
	}
	versionB, err := semver.NewVersion(string(versionStringB))
	if err != nil {
		return fmt.Errorf("operand 2: string %s is not a valid SemVer", versionStringB)
	}

	result := versionA.Compare(*versionB)

	return iter(ast.IntNumberTerm(result))
}

func builtinSemVerIsValid(bctx BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	versionString, err := builtins.StringOperand(args[0].Value, 1)
	if err != nil {
		result := ast.BooleanTerm(false)
		return iter(result)
	}

	result := true

	_, err = semver.NewVersion(string(versionString))
	if err != nil {
		result = false
	}

	return iter(ast.BooleanTerm(result))
}

func init() {
	RegisterBuiltinFunc(ast.SemVerCompare.Name, builtinSemVerCompare)
	RegisterBuiltinFunc(ast.SemVerIsValid.Name, builtinSemVerIsValid)
}
