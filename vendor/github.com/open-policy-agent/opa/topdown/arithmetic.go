// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"math/big"

	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

type arithArity1 func(a *big.Float) (*big.Float, error)
type arithArity2 func(a, b *big.Float) (*big.Float, error)

func arithAbs(a *big.Float) (*big.Float, error) {
	return a.Abs(a), nil
}

var halfAwayFromZero = big.NewFloat(0.5)

func arithRound(a *big.Float) (*big.Float, error) {
	var i *big.Int
	if a.Signbit() {
		i, _ = new(big.Float).Sub(a, halfAwayFromZero).Int(nil)
	} else {
		i, _ = new(big.Float).Add(a, halfAwayFromZero).Int(nil)
	}
	return new(big.Float).SetInt(i), nil
}

func arithCeil(a *big.Float) (*big.Float, error) {
	i, _ := a.Int(nil)
	f := new(big.Float).SetInt(i)

	if f.Signbit() || a.Cmp(f) == 0 {
		return f, nil
	}

	return new(big.Float).Add(f, big.NewFloat(1.0)), nil
}

func arithFloor(a *big.Float) (*big.Float, error) {
	i, _ := a.Int(nil)
	f := new(big.Float).SetInt(i)

	if !f.Signbit() || a.Cmp(f) == 0 {
		return f, nil
	}

	return new(big.Float).Sub(f, big.NewFloat(1.0)), nil
}

func arithPlus(a, b *big.Float) (*big.Float, error) {
	return new(big.Float).Add(a, b), nil
}

func arithMinus(a, b *big.Float) (*big.Float, error) {
	return new(big.Float).Sub(a, b), nil
}

func arithMultiply(a, b *big.Float) (*big.Float, error) {
	return new(big.Float).Mul(a, b), nil
}

func arithDivide(a, b *big.Float) (*big.Float, error) {
	i, acc := b.Int64()
	if acc == big.Exact && i == 0 {
		return nil, fmt.Errorf("divide by zero")
	}
	return new(big.Float).Quo(a, b), nil
}

func arithRem(a, b *big.Int) (*big.Int, error) {
	if b.Int64() == 0 {
		return nil, fmt.Errorf("modulo by zero")
	}
	return new(big.Int).Rem(a, b), nil
}

func builtinArithArity1(fn arithArity1) FunctionalBuiltin1 {
	return func(a ast.Value) (ast.Value, error) {
		n, err := builtins.NumberOperand(a, 1)
		if err != nil {
			return nil, err
		}
		f, err := fn(builtins.NumberToFloat(n))
		if err != nil {
			return nil, err
		}
		return builtins.FloatToNumber(f), nil
	}
}

func builtinArithArity2(fn arithArity2) FunctionalBuiltin2 {
	return func(a, b ast.Value) (ast.Value, error) {
		n1, err := builtins.NumberOperand(a, 1)
		if err != nil {
			return nil, err
		}
		n2, err := builtins.NumberOperand(b, 2)
		if err != nil {
			return nil, err
		}
		f, err := fn(builtins.NumberToFloat(n1), builtins.NumberToFloat(n2))
		if err != nil {
			return nil, err
		}
		return builtins.FloatToNumber(f), nil
	}
}

func builtinMinus(a, b ast.Value) (ast.Value, error) {

	n1, ok1 := a.(ast.Number)
	n2, ok2 := b.(ast.Number)

	if ok1 && ok2 {
		f, err := arithMinus(builtins.NumberToFloat(n1), builtins.NumberToFloat(n2))
		if err != nil {
			return nil, err
		}
		return builtins.FloatToNumber(f), nil
	}

	s1, ok3 := a.(ast.Set)
	s2, ok4 := b.(ast.Set)

	if ok3 && ok4 {
		return s1.Diff(s2), nil
	}

	if !ok1 && !ok3 {
		return nil, builtins.NewOperandTypeErr(1, a, "number", "set")
	}

	if ok2 {
		return nil, builtins.NewOperandTypeErr(2, b, "set")
	}

	return nil, builtins.NewOperandTypeErr(2, b, "number")
}

func builtinRem(a, b ast.Value) (ast.Value, error) {
	n1, ok1 := a.(ast.Number)
	n2, ok2 := b.(ast.Number)

	if ok1 && ok2 {

		op1, err1 := builtins.NumberToInt(n1)
		op2, err2 := builtins.NumberToInt(n2)

		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("modulo on floating-point number")
		}

		i, err := arithRem(op1, op2)
		if err != nil {
			return nil, err
		}
		return builtins.IntToNumber(i), nil
	}

	if !ok1 {
		return nil, builtins.NewOperandTypeErr(1, a, "number")
	}

	return nil, builtins.NewOperandTypeErr(2, b, "number")
}

func init() {
	RegisterFunctionalBuiltin1(ast.Abs.Name, builtinArithArity1(arithAbs))
	RegisterFunctionalBuiltin1(ast.Round.Name, builtinArithArity1(arithRound))
	RegisterFunctionalBuiltin1(ast.Ceil.Name, builtinArithArity1(arithCeil))
	RegisterFunctionalBuiltin1(ast.Floor.Name, builtinArithArity1(arithFloor))
	RegisterFunctionalBuiltin2(ast.Plus.Name, builtinArithArity2(arithPlus))
	RegisterFunctionalBuiltin2(ast.Minus.Name, builtinMinus)
	RegisterFunctionalBuiltin2(ast.Multiply.Name, builtinArithArity2(arithMultiply))
	RegisterFunctionalBuiltin2(ast.Divide.Name, builtinArithArity2(arithDivide))
	RegisterFunctionalBuiltin2(ast.Rem.Name, builtinRem)
}
