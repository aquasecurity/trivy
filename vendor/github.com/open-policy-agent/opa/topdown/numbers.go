// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"
	"math/big"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

type randIntCachingKey string

var one = big.NewInt(1)

func builtinNumbersRange(bctx BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {

	x, err := builtins.BigIntOperand(operands[0].Value, 1)
	if err != nil {
		return err
	}

	y, err := builtins.BigIntOperand(operands[1].Value, 2)
	if err != nil {
		return err
	}

	result := ast.NewArray()
	cmp := x.Cmp(y)
	haltErr := Halt{
		Err: &Error{
			Code:    CancelErr,
			Message: "numbers.range: timed out before generating all numbers in range",
		},
	}

	if cmp <= 0 {
		for i := new(big.Int).Set(x); i.Cmp(y) <= 0; i = i.Add(i, one) {
			if bctx.Cancel != nil && bctx.Cancel.Cancelled() {
				return haltErr
			}
			result = result.Append(ast.NewTerm(builtins.IntToNumber(i)))
		}
	} else {
		for i := new(big.Int).Set(x); i.Cmp(y) >= 0; i = i.Sub(i, one) {
			if bctx.Cancel != nil && bctx.Cancel.Cancelled() {
				return haltErr
			}
			result = result.Append(ast.NewTerm(builtins.IntToNumber(i)))
		}
	}

	return iter(ast.NewTerm(result))
}

func builtinRandIntn(bctx BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {

	strOp, err := builtins.StringOperand(args[0].Value, 1)
	if err != nil {
		return err

	}

	n, err := builtins.IntOperand(args[1].Value, 2)
	if err != nil {
		return err
	}

	if n == 0 {
		return iter(ast.IntNumberTerm(0))
	}

	if n < 0 {
		n = -n
	}

	var key = randIntCachingKey(fmt.Sprintf("%s-%d", strOp, n))

	if val, ok := bctx.Cache.Get(key); ok {
		return iter(val.(*ast.Term))
	}

	r, err := bctx.Rand()
	if err != nil {
		return err
	}
	result := ast.IntNumberTerm(r.Intn(n))
	bctx.Cache.Put(key, result)

	return iter(result)
}

func init() {
	RegisterBuiltinFunc(ast.NumbersRange.Name, builtinNumbersRange)
	RegisterBuiltinFunc(ast.RandIntn.Name, builtinRandIntn)
}
