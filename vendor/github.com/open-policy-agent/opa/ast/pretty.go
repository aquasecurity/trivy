// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"fmt"
	"io"
	"strings"
)

// Pretty writes a pretty representation of the AST rooted at x to w.
//
// This is function is intended for debug purposes when inspecting ASTs.
func Pretty(w io.Writer, x interface{}) {
	pp := &prettyPrinter{
		depth: -1,
		w:     w,
	}
	NewBeforeAfterVisitor(pp.Before, pp.After).Walk(x)
}

type prettyPrinter struct {
	depth int
	w     io.Writer
}

func (pp *prettyPrinter) Before(x interface{}) bool {
	switch x.(type) {
	case *Term:
	default:
		pp.depth++
	}

	switch x := x.(type) {
	case *Term:
		return false
	case Args:
		if len(x) == 0 {
			return false
		}
		pp.writeType(x)
	case *Expr:
		extras := []string{}
		if x.Negated {
			extras = append(extras, "negated")
		}
		extras = append(extras, fmt.Sprintf("index=%d", x.Index))
		pp.writeIndent("%v %v", TypeName(x), strings.Join(extras, " "))
	case Null, Boolean, Number, String, Var:
		pp.writeValue(x)
	default:
		pp.writeType(x)
	}
	return false
}

func (pp *prettyPrinter) After(x interface{}) {
	switch x.(type) {
	case *Term:
	default:
		pp.depth--
	}
}

func (pp *prettyPrinter) writeValue(x interface{}) {
	pp.writeIndent(fmt.Sprint(x))
}

func (pp *prettyPrinter) writeType(x interface{}) {
	pp.writeIndent(TypeName(x))
}

func (pp *prettyPrinter) writeIndent(f string, a ...interface{}) {
	pad := strings.Repeat(" ", pp.depth)
	pp.write(pad+f, a...)
}

func (pp *prettyPrinter) write(f string, a ...interface{}) {
	fmt.Fprintf(pp.w, f+"\n", a...)
}
