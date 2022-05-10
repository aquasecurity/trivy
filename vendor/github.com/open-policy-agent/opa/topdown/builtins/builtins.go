// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package builtins contains utilities for implementing built-in functions.
package builtins

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

// Cache defines the built-in cache used by the top-down evaluation. The keys
// must be comparable and should not be of type string.
type Cache map[interface{}]interface{}

// Put updates the cache for the named built-in.
func (c Cache) Put(k, v interface{}) {
	c[k] = v
}

// Get returns the cached value for k.
func (c Cache) Get(k interface{}) (interface{}, bool) {
	v, ok := c[k]
	return v, ok
}

// ErrOperand represents an invalid operand has been passed to a built-in
// function. Built-ins should return ErrOperand to indicate a type error has
// occurred.
type ErrOperand string

func (err ErrOperand) Error() string {
	return string(err)
}

// NewOperandErr returns a generic operand error.
func NewOperandErr(pos int, f string, a ...interface{}) error {
	f = fmt.Sprintf("operand %v ", pos) + f
	return ErrOperand(fmt.Sprintf(f, a...))
}

// NewOperandTypeErr returns an operand error indicating the operand's type was wrong.
func NewOperandTypeErr(pos int, got ast.Value, expected ...string) error {

	if len(expected) == 1 {
		return NewOperandErr(pos, "must be %v but got %v", expected[0], ast.TypeName(got))
	}

	return NewOperandErr(pos, "must be one of {%v} but got %v", strings.Join(expected, ", "), ast.TypeName(got))
}

// NewOperandElementErr returns an operand error indicating an element in the
// composite operand was wrong.
func NewOperandElementErr(pos int, composite ast.Value, got ast.Value, expected ...string) error {

	tpe := ast.TypeName(composite)

	if len(expected) == 1 {
		return NewOperandErr(pos, "must be %v of %vs but got %v containing %v", tpe, expected[0], tpe, ast.TypeName(got))
	}

	return NewOperandErr(pos, "must be %v of (any of) {%v} but got %v containing %v", tpe, strings.Join(expected, ", "), tpe, ast.TypeName(got))
}

// NewOperandEnumErr returns an operand error indicating a value was wrong.
func NewOperandEnumErr(pos int, expected ...string) error {

	if len(expected) == 1 {
		return NewOperandErr(pos, "must be %v", expected[0])
	}

	return NewOperandErr(pos, "must be one of {%v}", strings.Join(expected, ", "))
}

// IntOperand converts x to an int. If the cast fails, a descriptive error is
// returned.
func IntOperand(x ast.Value, pos int) (int, error) {
	n, ok := x.(ast.Number)
	if !ok {
		return 0, NewOperandTypeErr(pos, x, "number")
	}

	i, ok := n.Int()
	if !ok {
		return 0, NewOperandErr(pos, "must be integer number but got floating-point number")
	}

	return i, nil
}

// BigIntOperand converts x to a big int. If the cast fails, a descriptive error
// is returned.
func BigIntOperand(x ast.Value, pos int) (*big.Int, error) {
	n, err := NumberOperand(x, 1)
	if err != nil {
		return nil, NewOperandTypeErr(pos, x, "integer")
	}
	bi, err := NumberToInt(n)
	if err != nil {
		return nil, NewOperandErr(pos, "must be integer number but got floating-point number")
	}

	return bi, nil
}

// NumberOperand converts x to a number. If the cast fails, a descriptive error is
// returned.
func NumberOperand(x ast.Value, pos int) (ast.Number, error) {
	n, ok := x.(ast.Number)
	if !ok {
		return ast.Number(""), NewOperandTypeErr(pos, x, "number")
	}
	return n, nil
}

// SetOperand converts x to a set. If the cast fails, a descriptive error is
// returned.
func SetOperand(x ast.Value, pos int) (ast.Set, error) {
	s, ok := x.(ast.Set)
	if !ok {
		return nil, NewOperandTypeErr(pos, x, "set")
	}
	return s, nil
}

// StringOperand converts x to a string. If the cast fails, a descriptive error is
// returned.
func StringOperand(x ast.Value, pos int) (ast.String, error) {
	s, ok := x.(ast.String)
	if !ok {
		return ast.String(""), NewOperandTypeErr(pos, x, "string")
	}
	return s, nil
}

// ObjectOperand converts x to an object. If the cast fails, a descriptive
// error is returned.
func ObjectOperand(x ast.Value, pos int) (ast.Object, error) {
	o, ok := x.(ast.Object)
	if !ok {
		return nil, NewOperandTypeErr(pos, x, "object")
	}
	return o, nil
}

// ArrayOperand converts x to an array. If the cast fails, a descriptive
// error is returned.
func ArrayOperand(x ast.Value, pos int) (*ast.Array, error) {
	a, ok := x.(*ast.Array)
	if !ok {
		return ast.NewArray(), NewOperandTypeErr(pos, x, "array")
	}
	return a, nil
}

// NumberToFloat converts n to a big float.
func NumberToFloat(n ast.Number) *big.Float {
	r, ok := new(big.Float).SetString(string(n))
	if !ok {
		panic("illegal value")
	}
	return r
}

// FloatToNumber converts f to a number.
func FloatToNumber(f *big.Float) ast.Number {
	return ast.Number(f.Text('g', -1))
}

// NumberToInt converts n to a big int.
// If n cannot be converted to an big int, an error is returned.
func NumberToInt(n ast.Number) (*big.Int, error) {
	f := NumberToFloat(n)
	r, accuracy := f.Int(nil)
	if accuracy != big.Exact {
		return nil, fmt.Errorf("illegal value")
	}
	return r, nil
}

// IntToNumber converts i to a number.
func IntToNumber(i *big.Int) ast.Number {
	return ast.Number(i.String())
}

// StringSliceOperand converts x to a []string. If the cast fails, a descriptive error is
// returned.
func StringSliceOperand(x ast.Value, pos int) ([]string, error) {
	a, err := ArrayOperand(x, pos)
	if err != nil {
		return nil, err
	}

	var f = make([]string, a.Len())
	for k := 0; k < a.Len(); k++ {
		b := a.Elem(k)
		c, ok := b.Value.(ast.String)
		if !ok {
			return nil, NewOperandElementErr(pos, x, b.Value, "[]string")
		}

		f[k] = string(c)
	}

	return f, nil
}

// RuneSliceOperand converts x to a []rune. If the cast fails, a descriptive error is
// returned.
func RuneSliceOperand(x ast.Value, pos int) ([]rune, error) {
	a, err := ArrayOperand(x, pos)
	if err != nil {
		return nil, err
	}

	var f = make([]rune, a.Len())
	for k := 0; k < a.Len(); k++ {
		b := a.Elem(k)
		c, ok := b.Value.(ast.String)
		if !ok {
			return nil, NewOperandElementErr(pos, x, b.Value, "string")
		}

		d := []rune(string(c))
		if len(d) != 1 {
			return nil, NewOperandElementErr(pos, x, b.Value, "rune")
		}

		f[k] = d[0]
	}

	return f, nil
}
