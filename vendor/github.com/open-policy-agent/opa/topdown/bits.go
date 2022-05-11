// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"math/big"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

type bitsArity1 func(a *big.Int) (*big.Int, error)
type bitsArity2 func(a, b *big.Int) (*big.Int, error)

func bitsOr(a, b *big.Int) (*big.Int, error) {
	return new(big.Int).Or(a, b), nil
}

func bitsAnd(a, b *big.Int) (*big.Int, error) {
	return new(big.Int).And(a, b), nil
}

func bitsNegate(a *big.Int) (*big.Int, error) {
	return new(big.Int).Not(a), nil
}

func bitsXOr(a, b *big.Int) (*big.Int, error) {
	return new(big.Int).Xor(a, b), nil
}

func bitsShiftLeft(a, b *big.Int) (*big.Int, error) {
	if b.Sign() == -1 {
		return nil, builtins.NewOperandErr(2, "must be an unsigned integer number but got a negative integer")
	}
	shift := uint(b.Uint64())
	return new(big.Int).Lsh(a, shift), nil
}

func bitsShiftRight(a, b *big.Int) (*big.Int, error) {
	if b.Sign() == -1 {
		return nil, builtins.NewOperandErr(2, "must be an unsigned integer number but got a negative integer")
	}
	shift := uint(b.Uint64())
	return new(big.Int).Rsh(a, shift), nil
}

func builtinBitsArity1(fn bitsArity1) BuiltinFunc {
	return func(_ BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
		i, err := builtins.BigIntOperand(operands[0].Value, 1)
		if err != nil {
			return err
		}
		iOut, err := fn(i)
		if err != nil {
			return err
		}
		return iter(ast.NewTerm(builtins.IntToNumber(iOut)))
	}
}

func builtinBitsArity2(fn bitsArity2) BuiltinFunc {
	return func(_ BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
		i1, err := builtins.BigIntOperand(operands[0].Value, 1)
		if err != nil {
			return err
		}
		i2, err := builtins.BigIntOperand(operands[1].Value, 2)
		if err != nil {
			return err
		}
		iOut, err := fn(i1, i2)
		if err != nil {
			return err
		}
		return iter(ast.NewTerm(builtins.IntToNumber(iOut)))
	}
}

func init() {
	RegisterBuiltinFunc(ast.BitsOr.Name, builtinBitsArity2(bitsOr))
	RegisterBuiltinFunc(ast.BitsAnd.Name, builtinBitsArity2(bitsAnd))
	RegisterBuiltinFunc(ast.BitsNegate.Name, builtinBitsArity1(bitsNegate))
	RegisterBuiltinFunc(ast.BitsXOr.Name, builtinBitsArity2(bitsXOr))
	RegisterBuiltinFunc(ast.BitsShiftLeft.Name, builtinBitsArity2(bitsShiftLeft))
	RegisterBuiltinFunc(ast.BitsShiftRight.Name, builtinBitsArity2(bitsShiftRight))
}
