// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

func builtinFormatInt(a, b ast.Value) (ast.Value, error) {

	input, err := builtins.NumberOperand(a, 1)
	if err != nil {
		return nil, err
	}

	base, err := builtins.NumberOperand(b, 2)
	if err != nil {
		return nil, err
	}

	var format string
	switch base {
	case ast.Number("2"):
		format = "%b"
	case ast.Number("8"):
		format = "%o"
	case ast.Number("10"):
		format = "%d"
	case ast.Number("16"):
		format = "%x"
	default:
		return nil, builtins.NewOperandEnumErr(2, "2", "8", "10", "16")
	}

	f := builtins.NumberToFloat(input)
	i, _ := f.Int(nil)

	return ast.String(fmt.Sprintf(format, i)), nil
}

func builtinConcat(a, b ast.Value) (ast.Value, error) {

	join, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	strs := []string{}

	switch b := b.(type) {
	case *ast.Array:
		err := b.Iter(func(x *ast.Term) error {
			s, ok := x.Value.(ast.String)
			if !ok {
				return builtins.NewOperandElementErr(2, b, x.Value, "string")
			}
			strs = append(strs, string(s))
			return nil
		})
		if err != nil {
			return nil, err
		}
	case ast.Set:
		err := b.Iter(func(x *ast.Term) error {
			s, ok := x.Value.(ast.String)
			if !ok {
				return builtins.NewOperandElementErr(2, b, x.Value, "string")
			}
			strs = append(strs, string(s))
			return nil
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, builtins.NewOperandTypeErr(2, b, "set", "array")
	}

	return ast.String(strings.Join(strs, string(join))), nil
}

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func builtinIndexOf(a, b ast.Value) (ast.Value, error) {
	base, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	search, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}
	if len(string(search)) == 0 {
		return nil, fmt.Errorf("empty search character")
	}

	baseRunes := []rune(string(base))
	searchRunes := []rune(string(search))
	searchLen := len(searchRunes)

	for i, r := range baseRunes {
		if len(baseRunes) >= i+searchLen {
			if r == searchRunes[0] && runesEqual(baseRunes[i:i+searchLen], searchRunes) {
				return ast.IntNumberTerm(i).Value, nil
			}
		} else {
			break
		}
	}

	return ast.IntNumberTerm(-1).Value, nil
}

func builtinIndexOfN(a, b ast.Value) (ast.Value, error) {
	base, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	search, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}
	if len(string(search)) == 0 {
		return nil, fmt.Errorf("empty search character")
	}

	baseRunes := []rune(string(base))
	searchRunes := []rune(string(search))
	searchLen := len(searchRunes)

	var arr []*ast.Term
	for i, r := range baseRunes {
		if len(baseRunes) >= i+searchLen {
			if r == searchRunes[0] && runesEqual(baseRunes[i:i+searchLen], searchRunes) {
				arr = append(arr, ast.IntNumberTerm(i))
			}
		} else {
			break
		}
	}

	return ast.NewArray(arr...), nil
}

func builtinSubstring(a, b, c ast.Value) (ast.Value, error) {

	base, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}
	runes := []rune(base)

	startIndex, err := builtins.IntOperand(b, 2)
	if err != nil {
		return nil, err
	} else if startIndex >= len(runes) {
		return ast.String(""), nil
	} else if startIndex < 0 {
		return nil, fmt.Errorf("negative offset")
	}

	length, err := builtins.IntOperand(c, 3)
	if err != nil {
		return nil, err
	}

	var s ast.String
	if length < 0 {
		s = ast.String(runes[startIndex:])
	} else {
		upto := startIndex + length
		if len(runes) < upto {
			upto = len(runes)
		}
		s = ast.String(runes[startIndex:upto])
	}

	return s, nil
}

func builtinContains(a, b ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	substr, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}

	return ast.Boolean(strings.Contains(string(s), string(substr))), nil
}

func builtinStartsWith(a, b ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	prefix, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}

	return ast.Boolean(strings.HasPrefix(string(s), string(prefix))), nil
}

func builtinEndsWith(a, b ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	suffix, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}

	return ast.Boolean(strings.HasSuffix(string(s), string(suffix))), nil
}

func builtinLower(a ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	return ast.String(strings.ToLower(string(s))), nil
}

func builtinUpper(a ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	return ast.String(strings.ToUpper(string(s))), nil
}

func builtinSplit(a, b ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}
	d, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}
	elems := strings.Split(string(s), string(d))
	arr := make([]*ast.Term, len(elems))
	for i := range elems {
		arr[i] = ast.StringTerm(elems[i])
	}
	return ast.NewArray(arr...), nil
}

func builtinReplace(a, b, c ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	old, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}

	new, err := builtins.StringOperand(c, 3)
	if err != nil {
		return nil, err
	}

	return ast.String(strings.Replace(string(s), string(old), string(new), -1)), nil
}

func builtinReplaceN(a, b ast.Value) (ast.Value, error) {
	patterns, err := builtins.ObjectOperand(a, 1)
	if err != nil {
		return nil, err
	}
	keys := patterns.Keys()
	sort.Slice(keys, func(i, j int) bool { return ast.Compare(keys[i].Value, keys[j].Value) < 0 })

	s, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}

	var oldnewArr []string
	for _, k := range keys {
		keyVal, ok := k.Value.(ast.String)
		if !ok {
			return nil, builtins.NewOperandErr(1, "non-string key found in pattern object")
		}
		val := patterns.Get(k) // cannot be nil
		strVal, ok := val.Value.(ast.String)
		if !ok {
			return nil, builtins.NewOperandErr(1, "non-string value found in pattern object")
		}
		oldnewArr = append(oldnewArr, string(keyVal), string(strVal))
	}
	if err != nil {
		return nil, err
	}

	r := strings.NewReplacer(oldnewArr...)
	replaced := r.Replace(string(s))

	return ast.String(replaced), nil
}

func builtinTrim(a, b ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	c, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}

	return ast.String(strings.Trim(string(s), string(c))), nil
}

func builtinTrimLeft(a, b ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	c, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}

	return ast.String(strings.TrimLeft(string(s), string(c))), nil
}

func builtinTrimPrefix(a, b ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	pre, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}

	return ast.String(strings.TrimPrefix(string(s), string(pre))), nil
}

func builtinTrimRight(a, b ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	c, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}

	return ast.String(strings.TrimRight(string(s), string(c))), nil
}

func builtinTrimSuffix(a, b ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	suf, err := builtins.StringOperand(b, 2)
	if err != nil {
		return nil, err
	}

	return ast.String(strings.TrimSuffix(string(s), string(suf))), nil
}

func builtinTrimSpace(a ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	return ast.String(strings.TrimSpace(string(s))), nil
}

func builtinSprintf(a, b ast.Value) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	astArr, ok := b.(*ast.Array)
	if !ok {
		return nil, builtins.NewOperandTypeErr(2, b, "array")
	}

	args := make([]interface{}, astArr.Len())

	for i := range args {
		switch v := astArr.Elem(i).Value.(type) {
		case ast.Number:
			if n, ok := v.Int(); ok {
				args[i] = n
			} else if b, ok := new(big.Int).SetString(v.String(), 10); ok {
				args[i] = b
			} else if f, ok := v.Float64(); ok {
				args[i] = f
			} else {
				args[i] = v.String()
			}
		case ast.String:
			args[i] = string(v)
		default:
			args[i] = astArr.Elem(i).String()
		}
	}

	return ast.String(fmt.Sprintf(string(s), args...)), nil
}

func builtinReverse(bctx BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	s, err := builtins.StringOperand(operands[0].Value, 1)
	if err != nil {
		return err
	}

	sRunes := []rune(string(s))
	length := len(sRunes)
	reversedRunes := make([]rune, length)

	for index, r := range sRunes {
		reversedRunes[length-index-1] = r
	}

	reversedString := string(reversedRunes)

	return iter(ast.StringTerm(reversedString))
}

func init() {
	RegisterFunctionalBuiltin2(ast.FormatInt.Name, builtinFormatInt)
	RegisterFunctionalBuiltin2(ast.Concat.Name, builtinConcat)
	RegisterFunctionalBuiltin2(ast.IndexOf.Name, builtinIndexOf)
	RegisterFunctionalBuiltin2(ast.IndexOfN.Name, builtinIndexOfN)
	RegisterFunctionalBuiltin3(ast.Substring.Name, builtinSubstring)
	RegisterFunctionalBuiltin2(ast.Contains.Name, builtinContains)
	RegisterFunctionalBuiltin2(ast.StartsWith.Name, builtinStartsWith)
	RegisterFunctionalBuiltin2(ast.EndsWith.Name, builtinEndsWith)
	RegisterFunctionalBuiltin1(ast.Upper.Name, builtinUpper)
	RegisterFunctionalBuiltin1(ast.Lower.Name, builtinLower)
	RegisterFunctionalBuiltin2(ast.Split.Name, builtinSplit)
	RegisterFunctionalBuiltin3(ast.Replace.Name, builtinReplace)
	RegisterFunctionalBuiltin2(ast.ReplaceN.Name, builtinReplaceN)
	RegisterFunctionalBuiltin2(ast.Trim.Name, builtinTrim)
	RegisterFunctionalBuiltin2(ast.TrimLeft.Name, builtinTrimLeft)
	RegisterFunctionalBuiltin2(ast.TrimPrefix.Name, builtinTrimPrefix)
	RegisterFunctionalBuiltin2(ast.TrimRight.Name, builtinTrimRight)
	RegisterFunctionalBuiltin2(ast.TrimSuffix.Name, builtinTrimSuffix)
	RegisterFunctionalBuiltin1(ast.TrimSpace.Name, builtinTrimSpace)
	RegisterFunctionalBuiltin2(ast.Sprintf.Name, builtinSprintf)
	RegisterBuiltinFunc(ast.StringReverse.Name, builtinReverse)
}
