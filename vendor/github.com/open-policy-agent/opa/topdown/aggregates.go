// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"math/big"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

func builtinCount(a ast.Value) (ast.Value, error) {
	switch a := a.(type) {
	case *ast.Array:
		return ast.IntNumberTerm(a.Len()).Value, nil
	case ast.Object:
		return ast.IntNumberTerm(a.Len()).Value, nil
	case ast.Set:
		return ast.IntNumberTerm(a.Len()).Value, nil
	case ast.String:
		return ast.IntNumberTerm(len([]rune(a))).Value, nil
	}
	return nil, builtins.NewOperandTypeErr(1, a, "array", "object", "set")
}

func builtinSum(a ast.Value) (ast.Value, error) {
	switch a := a.(type) {
	case *ast.Array:
		sum := big.NewFloat(0)
		err := a.Iter(func(x *ast.Term) error {
			n, ok := x.Value.(ast.Number)
			if !ok {
				return builtins.NewOperandElementErr(1, a, x.Value, "number")
			}
			sum = new(big.Float).Add(sum, builtins.NumberToFloat(n))
			return nil
		})
		return builtins.FloatToNumber(sum), err
	case ast.Set:
		sum := big.NewFloat(0)
		err := a.Iter(func(x *ast.Term) error {
			n, ok := x.Value.(ast.Number)
			if !ok {
				return builtins.NewOperandElementErr(1, a, x.Value, "number")
			}
			sum = new(big.Float).Add(sum, builtins.NumberToFloat(n))
			return nil
		})
		return builtins.FloatToNumber(sum), err
	}
	return nil, builtins.NewOperandTypeErr(1, a, "set", "array")
}

func builtinProduct(a ast.Value) (ast.Value, error) {
	switch a := a.(type) {
	case *ast.Array:
		product := big.NewFloat(1)
		err := a.Iter(func(x *ast.Term) error {
			n, ok := x.Value.(ast.Number)
			if !ok {
				return builtins.NewOperandElementErr(1, a, x.Value, "number")
			}
			product = new(big.Float).Mul(product, builtins.NumberToFloat(n))
			return nil
		})
		return builtins.FloatToNumber(product), err
	case ast.Set:
		product := big.NewFloat(1)
		err := a.Iter(func(x *ast.Term) error {
			n, ok := x.Value.(ast.Number)
			if !ok {
				return builtins.NewOperandElementErr(1, a, x.Value, "number")
			}
			product = new(big.Float).Mul(product, builtins.NumberToFloat(n))
			return nil
		})
		return builtins.FloatToNumber(product), err
	}
	return nil, builtins.NewOperandTypeErr(1, a, "set", "array")
}

func builtinMax(a ast.Value) (ast.Value, error) {
	switch a := a.(type) {
	case *ast.Array:
		if a.Len() == 0 {
			return nil, BuiltinEmpty{}
		}
		var max = ast.Value(ast.Null{})
		a.Foreach(func(x *ast.Term) {
			if ast.Compare(max, x.Value) <= 0 {
				max = x.Value
			}
		})
		return max, nil
	case ast.Set:
		if a.Len() == 0 {
			return nil, BuiltinEmpty{}
		}
		max, err := a.Reduce(ast.NullTerm(), func(max *ast.Term, elem *ast.Term) (*ast.Term, error) {
			if ast.Compare(max, elem) <= 0 {
				return elem, nil
			}
			return max, nil
		})
		return max.Value, err
	}

	return nil, builtins.NewOperandTypeErr(1, a, "set", "array")
}

func builtinMin(a ast.Value) (ast.Value, error) {
	switch a := a.(type) {
	case *ast.Array:
		if a.Len() == 0 {
			return nil, BuiltinEmpty{}
		}
		min := a.Elem(0).Value
		a.Foreach(func(x *ast.Term) {
			if ast.Compare(min, x.Value) >= 0 {
				min = x.Value
			}
		})
		return min, nil
	case ast.Set:
		if a.Len() == 0 {
			return nil, BuiltinEmpty{}
		}
		min, err := a.Reduce(ast.NullTerm(), func(min *ast.Term, elem *ast.Term) (*ast.Term, error) {
			// The null term is considered to be less than any other term,
			// so in order for min of a set to make sense, we need to check
			// for it.
			if min.Value.Compare(ast.Null{}) == 0 {
				return elem, nil
			}

			if ast.Compare(min, elem) >= 0 {
				return elem, nil
			}
			return min, nil
		})
		return min.Value, err
	}

	return nil, builtins.NewOperandTypeErr(1, a, "set", "array")
}

func builtinSort(a ast.Value) (ast.Value, error) {
	switch a := a.(type) {
	case *ast.Array:
		return a.Sorted(), nil
	case ast.Set:
		return a.Sorted(), nil
	}
	return nil, builtins.NewOperandTypeErr(1, a, "set", "array")
}

func builtinAll(a ast.Value) (ast.Value, error) {
	switch val := a.(type) {
	case ast.Set:
		res := true
		match := ast.BooleanTerm(true)
		val.Until(func(term *ast.Term) bool {
			if !match.Equal(term) {
				res = false
				return true
			}
			return false
		})
		return ast.Boolean(res), nil
	case *ast.Array:
		res := true
		match := ast.BooleanTerm(true)
		val.Until(func(term *ast.Term) bool {
			if !match.Equal(term) {
				res = false
				return true
			}
			return false
		})
		return ast.Boolean(res), nil
	default:
		return nil, builtins.NewOperandTypeErr(1, a, "array", "set")
	}
}

func builtinAny(a ast.Value) (ast.Value, error) {
	switch val := a.(type) {
	case ast.Set:
		res := val.Len() > 0 && val.Contains(ast.BooleanTerm(true))
		return ast.Boolean(res), nil
	case *ast.Array:
		res := false
		match := ast.BooleanTerm(true)
		val.Until(func(term *ast.Term) bool {
			if match.Equal(term) {
				res = true
				return true
			}
			return false
		})
		return ast.Boolean(res), nil
	default:
		return nil, builtins.NewOperandTypeErr(1, a, "array", "set")
	}
}

func builtinMember(_ BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	containee := args[0]
	switch c := args[1].Value.(type) {
	case ast.Set:
		return iter(ast.BooleanTerm(c.Contains(containee)))
	case *ast.Array:
		ret := false
		c.Until(func(v *ast.Term) bool {
			if v.Value.Compare(containee.Value) == 0 {
				ret = true
			}
			return ret
		})
		return iter(ast.BooleanTerm(ret))
	case ast.Object:
		ret := false
		c.Until(func(_, v *ast.Term) bool {
			if v.Value.Compare(containee.Value) == 0 {
				ret = true
			}
			return ret
		})
		return iter(ast.BooleanTerm(ret))
	}
	return iter(ast.BooleanTerm(false))
}

func builtinMemberWithKey(_ BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	key, val := args[0], args[1]
	switch c := args[2].Value.(type) {
	case interface{ Get(*ast.Term) *ast.Term }:
		ret := false
		if act := c.Get(key); act != nil {
			ret = act.Value.Compare(val.Value) == 0
		}
		return iter(ast.BooleanTerm(ret))
	}
	return iter(ast.BooleanTerm(false))
}

func init() {
	RegisterFunctionalBuiltin1(ast.Count.Name, builtinCount)
	RegisterFunctionalBuiltin1(ast.Sum.Name, builtinSum)
	RegisterFunctionalBuiltin1(ast.Product.Name, builtinProduct)
	RegisterFunctionalBuiltin1(ast.Max.Name, builtinMax)
	RegisterFunctionalBuiltin1(ast.Min.Name, builtinMin)
	RegisterFunctionalBuiltin1(ast.Sort.Name, builtinSort)
	RegisterFunctionalBuiltin1(ast.Any.Name, builtinAny)
	RegisterFunctionalBuiltin1(ast.All.Name, builtinAll)
	RegisterBuiltinFunc(ast.Member.Name, builtinMember)
	RegisterBuiltinFunc(ast.MemberWithKey.Name, builtinMemberWithKey)
}
