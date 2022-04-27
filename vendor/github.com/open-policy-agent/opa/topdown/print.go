// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"
	"io"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/topdown/print"
)

func NewPrintHook(w io.Writer) print.Hook {
	return printHook{w: w}
}

type printHook struct {
	w io.Writer
}

func (h printHook) Print(_ print.Context, msg string) error {
	_, err := fmt.Fprintln(h.w, msg)
	return err
}

func builtinPrint(bctx BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {

	if bctx.PrintHook == nil {
		return iter(nil)
	}

	arr, err := builtins.ArrayOperand(operands[0].Value, 1)
	if err != nil {
		return err
	}

	buf := make([]string, arr.Len())

	err = builtinPrintCrossProductOperands(bctx, buf, arr, 0, func(buf []string) error {
		pctx := print.Context{
			Context:  bctx.Context,
			Location: bctx.Location,
		}
		return bctx.PrintHook.Print(pctx, strings.Join(buf, " "))
	})
	if err != nil {
		return err
	}

	return iter(nil)
}

func builtinPrintCrossProductOperands(bctx BuiltinContext, buf []string, operands *ast.Array, i int, f func([]string) error) error {

	if i >= operands.Len() {
		return f(buf)
	}

	xs, ok := operands.Elem(i).Value.(ast.Set)
	if !ok {
		return Halt{Err: internalErr(bctx.Location, fmt.Sprintf("illegal argument type: %v", ast.TypeName(operands.Elem(i).Value)))}
	}

	if xs.Len() == 0 {
		buf[i] = "<undefined>"
		return builtinPrintCrossProductOperands(bctx, buf, operands, i+1, f)
	}

	return xs.Iter(func(x *ast.Term) error {
		switch v := x.Value.(type) {
		case ast.String:
			buf[i] = string(v)
		default:
			buf[i] = v.String()
		}
		return builtinPrintCrossProductOperands(bctx, buf, operands, i+1, f)
	})
}

func init() {
	RegisterBuiltinFunc(ast.InternalPrint.Name, builtinPrint)
}
