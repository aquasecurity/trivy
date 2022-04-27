// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package format implements formatting of Rego source files.
package format

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"

	"github.com/open-policy-agent/opa/ast"
)

// defaultLocationFile is the file name used in `Ast()` for terms
// without a location, as could happen when pretty-printing the
// results of partial eval.
const defaultLocationFile = "__format_default__"

// Source formats a Rego source file. The bytes provided must describe a complete
// Rego module. If they don't, Source will return an error resulting from the attempt
// to parse the bytes.
func Source(filename string, src []byte) ([]byte, error) {
	module, err := ast.ParseModule(filename, string(src))
	if err != nil {
		return nil, err
	}
	formatted, err := Ast(module)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", filename, err)
	}
	return formatted, nil
}

// MustAst is a helper function to format a Rego AST element. If any errors
// occurs this function will panic. This is mostly used for test
func MustAst(x interface{}) []byte {
	bs, err := Ast(x)
	if err != nil {
		panic(err)
	}
	return bs
}

// Ast formats a Rego AST element. If the passed value is not a valid AST
// element, Ast returns nil and an error. If AST nodes are missing locations
// an arbitrary location will be used.
func Ast(x interface{}) ([]byte, error) {

	// The node has to be deep copied because it may be mutated below. Alternatively,
	// we could avoid the copy by checking if mutation will occur first. For now,
	// since format is not latency sensitive, just deep copy in all cases.
	x = ast.Copy(x)

	wildcards := map[ast.Var]*ast.Term{}

	// NOTE(sr): When the formatter encounters a call to internal.member_2
	// or internal.member_3, it will sugarize them into usage of the `in`
	// operator. It has to ensure that the proper future keyword import is
	// present.
	extraFutureKeywordImports := map[string]bool{}

	// Preprocess the AST. Set any required defaults and calculate
	// values required for printing the formatted output.
	ast.WalkNodes(x, func(x ast.Node) bool {
		switch n := x.(type) {
		case ast.Body:
			if len(n) == 0 {
				return false
			}
		case *ast.Term:
			unmangleWildcardVar(wildcards, n)

		case *ast.Expr:
			switch {
			case n.IsCall() && ast.Member.Ref().Equal(n.Operator()) || ast.MemberWithKey.Ref().Equal(n.Operator()):
				extraFutureKeywordImports["in"] = true
			case n.IsEvery():
				extraFutureKeywordImports["every"] = true
			}
		}
		if x.Loc() == nil {
			x.SetLoc(defaultLocation(x))
		}
		return false
	})

	w := &writer{
		indent: "\t",
	}

	switch x := x.(type) {
	case *ast.Module:
		for kw := range extraFutureKeywordImports {
			x.Imports = ensureFutureKeywordImport(x.Imports, kw)
		}
		w.writeModule(x)
	case *ast.Package:
		w.writePackage(x, nil)
	case *ast.Import:
		w.writeImports([]*ast.Import{x}, nil)
	case *ast.Rule:
		w.writeRule(x, false, nil)
	case *ast.Head:
		w.writeHead(x, false, false, nil)
	case ast.Body:
		w.writeBody(x, nil)
	case *ast.Expr:
		w.writeExpr(x, nil)
	case *ast.With:
		w.writeWith(x, nil, false)
	case *ast.Term:
		w.writeTerm(x, nil)
	case ast.Value:
		w.writeTerm(&ast.Term{Value: x, Location: &ast.Location{}}, nil)
	case *ast.Comment:
		w.writeComments([]*ast.Comment{x})
	default:
		return nil, fmt.Errorf("not an ast element: %v", x)
	}

	return squashTrailingNewlines(w.buf.Bytes()), nil
}

func unmangleWildcardVar(wildcards map[ast.Var]*ast.Term, n *ast.Term) {

	v, ok := n.Value.(ast.Var)
	if !ok || !v.IsWildcard() {
		return
	}

	first, ok := wildcards[v]
	if !ok {
		wildcards[v] = n
		return
	}

	w := v[len(ast.WildcardPrefix):]

	// Prepend an underscore to ensure the variable will parse.
	if len(w) == 0 || w[0] != '_' {
		w = "_" + w
	}

	if first != nil {
		first.Value = w
		wildcards[v] = nil
	}

	n.Value = w
}

func squashTrailingNewlines(bs []byte) []byte {
	if bytes.HasSuffix(bs, []byte("\n")) {
		return append(bytes.TrimRight(bs, "\n"), '\n')
	}
	return bs
}

func defaultLocation(x ast.Node) *ast.Location {
	return ast.NewLocation([]byte(x.String()), defaultLocationFile, 1, 1)
}

type writer struct {
	buf bytes.Buffer

	indent    string
	level     int
	inline    bool
	beforeEnd *ast.Comment
	delay     bool
}

func (w *writer) writeModule(module *ast.Module) {
	var pkg *ast.Package
	var others []interface{}
	var comments []*ast.Comment
	visitor := ast.NewGenericVisitor(func(x interface{}) bool {
		switch x := x.(type) {
		case *ast.Comment:
			comments = append(comments, x)
			return true
		case *ast.Import, *ast.Rule:
			others = append(others, x)
			return true
		case *ast.Package:
			pkg = x
			return true
		default:
			return false
		}
	})
	visitor.Walk(module)

	sort.Slice(comments, func(i, j int) bool {
		return locLess(comments[i], comments[j])
	})

	// XXX: The parser currently duplicates comments for some reason, so we need
	// to remove duplicates here.
	comments = dedupComments(comments)
	sort.Slice(others, func(i, j int) bool {
		return locLess(others[i], others[j])
	})

	comments = w.writePackage(pkg, comments)
	var imports []*ast.Import
	var rules []*ast.Rule
	for len(others) > 0 {
		imports, others = gatherImports(others)
		comments = w.writeImports(imports, comments)
		rules, others = gatherRules(others)
		comments = w.writeRules(rules, comments)
	}

	for i, c := range comments {
		w.writeLine(c.String())
		if i == len(comments)-1 {
			w.write("\n")
		}
	}
}

func (w *writer) writePackage(pkg *ast.Package, comments []*ast.Comment) []*ast.Comment {
	comments = w.insertComments(comments, pkg.Location)

	w.startLine()
	w.write(pkg.String())
	w.blankLine()

	return comments
}

func (w *writer) writeComments(comments []*ast.Comment) {
	for i := 0; i < len(comments); i++ {
		if i > 0 && locCmp(comments[i], comments[i-1]) > 1 {
			w.blankLine()
		}
		w.writeLine(comments[i].String())
	}
}

func (w *writer) writeRules(rules []*ast.Rule, comments []*ast.Comment) []*ast.Comment {
	for _, rule := range rules {
		comments = w.insertComments(comments, rule.Location)
		comments = w.writeRule(rule, false, comments)
		w.blankLine()
	}
	return comments
}

func (w *writer) writeRule(rule *ast.Rule, isElse bool, comments []*ast.Comment) []*ast.Comment {
	if rule == nil {
		return comments
	}

	if !isElse {
		w.startLine()
	}

	if rule.Default {
		w.write("default ")
	}

	// OPA transforms lone bodies like `foo = {"a": "b"}` into rules of the form
	// `foo = {"a": "b"} { true }` in the AST. We want to preserve that notation
	// in the formatted code instead of expanding the bodies into rules, so we
	// pretend that the rule has no body in this case.
	isExpandedConst := rule.Body.Equal(ast.NewBody(ast.NewExpr(ast.BooleanTerm(true)))) && rule.Else == nil

	comments = w.writeHead(rule.Head, rule.Default, isExpandedConst, comments)

	if (len(rule.Body) == 0 || isExpandedConst) && !isElse {
		w.endLine()
		return comments
	}

	w.write(" {")
	w.endLine()
	w.up()

	comments = w.writeBody(rule.Body, comments)

	var closeLoc *ast.Location

	if len(rule.Head.Args) > 0 {
		closeLoc = closingLoc('(', ')', '{', '}', rule.Location)
	} else {
		closeLoc = closingLoc('[', ']', '{', '}', rule.Location)
	}

	comments = w.insertComments(comments, closeLoc)

	w.down()
	w.startLine()
	w.write("}")
	if rule.Else != nil {
		comments = w.writeElse(rule, comments)
	}
	return comments
}

func (w *writer) writeElse(rule *ast.Rule, comments []*ast.Comment) []*ast.Comment {
	// If there was nothing else on the line before the "else" starts
	// then preserve this style of else block, otherwise it will be
	// started as an "inline" else eg:
	//
	//     p {
	//     	...
	//     }
	//
	//     else {
	//     	...
	//     }
	//
	// versus
	//
	//     p {
	// 	    ...
	//     } else {
	//     	...
	//     }
	//
	// Note: This doesn't use the `close` as it currently isn't accurate for all
	// types of values. Checking the actual line text is the most consistent approach.
	wasInline := false
	ruleLines := bytes.Split(rule.Location.Text, []byte("\n"))
	relativeElseRow := rule.Else.Location.Row - rule.Location.Row
	if relativeElseRow > 0 && relativeElseRow < len(ruleLines) {
		elseLine := ruleLines[relativeElseRow]
		if !bytes.HasPrefix(bytes.TrimSpace(elseLine), []byte("else")) {
			wasInline = true
		}
	}

	// If there are any comments between the closing brace of the previous rule and the start
	// of the else block we will always insert a new blank line between them.
	hasCommentAbove := len(comments) > 0 && comments[0].Location.Row-rule.Else.Head.Location.Row < 0 || w.beforeEnd != nil

	if !hasCommentAbove && wasInline {
		w.write(" ")
	} else {
		w.blankLine()
		w.startLine()
	}

	rule.Else.Head.Name = "else"
	rule.Else.Head.Args = nil
	comments = w.insertComments(comments, rule.Else.Head.Location)

	if hasCommentAbove && !wasInline {
		// The comments would have ended the line, be sure to start one again
		// before writing the rest of the "else" rule.
		w.startLine()
	}

	// For backwards compatibility adjust the rule head value location
	// TODO: Refactor the logic for inserting comments, or special
	// case comments in a rule head value so this can be removed
	if rule.Else.Head.Value != nil {
		rule.Else.Head.Value.Location = rule.Else.Head.Location
	}

	return w.writeRule(rule.Else, true, comments)
}

func (w *writer) writeHead(head *ast.Head, isDefault bool, isExpandedConst bool, comments []*ast.Comment) []*ast.Comment {
	w.write(head.Name.String())
	if len(head.Args) > 0 {
		w.write("(")
		var args []interface{}
		for _, arg := range head.Args {
			args = append(args, arg)
		}
		comments = w.writeIterable(args, head.Location, closingLoc(0, 0, '(', ')', head.Location), comments, w.listWriter())
		w.write(")")
	}
	if head.Key != nil {
		w.write("[")
		comments = w.writeTerm(head.Key, comments)
		w.write("]")
	}
	if head.Value != nil && (head.Key != nil || ast.Compare(head.Value, ast.BooleanTerm(true)) != 0 || isExpandedConst || isDefault) {
		if head.Assign {
			w.write(" := ")
		} else {
			w.write(" = ")
		}
		comments = w.writeTerm(head.Value, comments)
	}
	return comments
}

func (w *writer) insertComments(comments []*ast.Comment, loc *ast.Location) []*ast.Comment {
	before, at, comments := partitionComments(comments, loc)
	w.writeComments(before)
	if len(before) > 0 && loc.Row-before[len(before)-1].Location.Row > 1 {
		w.blankLine()
	}

	w.beforeLineEnd(at)
	return comments
}

func (w *writer) writeBody(body ast.Body, comments []*ast.Comment) []*ast.Comment {
	comments = w.insertComments(comments, body.Loc())
	offset := 0
	for i, expr := range body {
		if i > 0 && expr.Location.Row-body[i-1].Location.Row-offset > 1 {
			w.blankLine()
		}
		w.startLine()

		comments = w.writeExpr(expr, comments)
		w.endLine()
	}
	return comments
}

func (w *writer) writeExpr(expr *ast.Expr, comments []*ast.Comment) []*ast.Comment {
	comments = w.insertComments(comments, expr.Location)
	if !w.inline {
		w.startLine()
	}

	if expr.Negated {
		w.write("not ")
	}

	switch t := expr.Terms.(type) {
	case *ast.SomeDecl:
		comments = w.writeSomeDecl(t, comments)
	case *ast.Every:
		comments = w.writeEvery(t, comments)
	case []*ast.Term:
		comments = w.writeFunctionCall(expr, comments)
	case *ast.Term:
		comments = w.writeTerm(t, comments)
	}

	var indented bool
	for i, with := range expr.With {
		if i > 0 && with.Location.Row-expr.With[i-1].Location.Row > 0 {
			if !indented {
				indented = true

				w.up()
				defer w.down()
			}
			w.endLine()
			w.startLine()
		}
		comments = w.writeWith(with, comments, indented)
	}

	return comments
}

func (w *writer) writeSomeDecl(decl *ast.SomeDecl, comments []*ast.Comment) []*ast.Comment {
	comments = w.insertComments(comments, decl.Location)
	w.write("some ")

	row := decl.Location.Row

	for i, term := range decl.Symbols {
		switch val := term.Value.(type) {
		case ast.Var:
			if term.Location.Row > row {
				w.endLine()
				w.startLine()
				w.write(w.indent)
				row = term.Location.Row
			} else if i > 0 {
				w.write(" ")
			}

			comments = w.writeTerm(term, comments)

			if i < len(decl.Symbols)-1 {
				w.write(",")
			}
		case ast.Call:
			comments = w.writeInOperator(false, val[1:], comments)
		}
	}

	return comments
}

func (w *writer) writeEvery(every *ast.Every, comments []*ast.Comment) []*ast.Comment {
	comments = w.insertComments(comments, every.Location)
	w.write("every ")
	if every.Key != nil {
		comments = w.writeTerm(every.Key, comments)
		w.write(", ")
	}
	comments = w.writeTerm(every.Value, comments)
	w.write(" in ")
	comments = w.writeTerm(every.Domain, comments)
	w.write(" {")
	comments = w.writeComprehensionBody('{', '}', every.Body, every.Loc(), every.Loc(), comments)

	if len(every.Body) == 1 &&
		every.Body[0].Location.Row == every.Location.Row {
		w.write(" ")
	}
	w.write("}")
	return comments
}

func (w *writer) writeFunctionCall(expr *ast.Expr, comments []*ast.Comment) []*ast.Comment {

	terms := expr.Terms.([]*ast.Term)
	operator := terms[0].Value.String()

	switch operator {
	case ast.Member.Name, ast.MemberWithKey.Name:
		return w.writeInOperator(false, terms[1:], comments)
	}

	bi, ok := ast.BuiltinMap[operator]
	if !ok || bi.Infix == "" {
		return w.writeFunctionCallPlain(terms, comments)
	}

	numDeclArgs := len(bi.Decl.Args())
	numCallArgs := len(terms) - 1

	switch numCallArgs {
	case numDeclArgs: // Print infix where result is unassigned (e.g., x != y)
		comments = w.writeTerm(terms[1], comments)
		w.write(" " + bi.Infix + " ")
		return w.writeTerm(terms[2], comments)

	case numDeclArgs + 1: // Print infix where result is assigned (e.g., z = x + y)
		comments = w.writeTerm(terms[3], comments)
		w.write(" " + ast.Equality.Infix + " ")
		comments = w.writeTerm(terms[1], comments)
		w.write(" " + bi.Infix + " ")
		comments = w.writeTerm(terms[2], comments)
		return comments
	}
	return w.writeFunctionCallPlain(terms, comments)
}

func (w *writer) writeFunctionCallPlain(terms []*ast.Term, comments []*ast.Comment) []*ast.Comment {
	w.write(terms[0].String() + "(")
	defer w.write(")")
	args := make([]interface{}, len(terms)-1)
	for i, t := range terms[1:] {
		args[i] = t
	}
	loc := terms[0].Location
	return w.writeIterable(args, loc, closingLoc(0, 0, '(', ')', loc), comments, w.listWriter())
}

func (w *writer) writeWith(with *ast.With, comments []*ast.Comment, indented bool) []*ast.Comment {
	comments = w.insertComments(comments, with.Location)
	if !indented {
		w.write(" ")
	}
	w.write("with ")
	comments = w.writeTerm(with.Target, comments)
	w.write(" as ")
	return w.writeTerm(with.Value, comments)
}

func (w *writer) writeTerm(term *ast.Term, comments []*ast.Comment) []*ast.Comment {
	return w.writeTermParens(false, term, comments)
}

func (w *writer) writeTermParens(parens bool, term *ast.Term, comments []*ast.Comment) []*ast.Comment {
	comments = w.insertComments(comments, term.Location)
	if !w.inline {
		w.startLine()
	}

	switch x := term.Value.(type) {
	case ast.Ref:
		w.writeRef(x)
	case ast.Object:
		comments = w.writeObject(x, term.Location, comments)
	case *ast.Array:
		comments = w.writeArray(x, term.Location, comments)
	case ast.Set:
		comments = w.writeSet(x, term.Location, comments)
	case *ast.ArrayComprehension:
		comments = w.writeArrayComprehension(x, term.Location, comments)
	case *ast.ObjectComprehension:
		comments = w.writeObjectComprehension(x, term.Location, comments)
	case *ast.SetComprehension:
		comments = w.writeSetComprehension(x, term.Location, comments)
	case ast.String:
		if term.Location.Text[0] == '`' {
			// To preserve raw strings, we need to output the original text,
			// not what x.String() would give us.
			w.write(string(term.Location.Text))
		} else {
			w.write(x.String())
		}
	case ast.Var:
		w.write(w.formatVar(x))
	case ast.Call:
		comments = w.writeCall(parens, x, comments)
	case fmt.Stringer:
		w.write(x.String())
	}

	if !w.inline {
		w.startLine()
	}
	return comments
}

func (w *writer) writeRef(x ast.Ref) {
	if len(x) > 0 {
		w.writeTerm(x[0], nil)
		path := x[1:]
		for _, t := range path {
			switch p := t.Value.(type) {
			case ast.String:
				w.writeRefStringPath(p)
			case ast.Var:
				w.writeBracketed(w.formatVar(p))
			default:
				w.write("[")
				w.writeTerm(t, nil)
				w.write("]")
			}
		}
	}
}

func (w *writer) writeBracketed(str string) {
	w.write("[" + str + "]")
}

var varRegexp = regexp.MustCompile("^[[:alpha:]_][[:alpha:][:digit:]_]*$")

func (w *writer) writeRefStringPath(s ast.String) {
	str := string(s)
	if varRegexp.MatchString(str) && !ast.IsKeyword(str) {
		w.write("." + str)
	} else {
		w.writeBracketed(s.String())
	}
}

func (w *writer) formatVar(v ast.Var) string {
	if v.IsWildcard() {
		return ast.Wildcard.String()
	}
	return v.String()
}

func (w *writer) writeCall(parens bool, x ast.Call, comments []*ast.Comment) []*ast.Comment {
	bi, ok := ast.BuiltinMap[x[0].String()]
	if !ok || bi.Infix == "" {
		return w.writeFunctionCallPlain(x, comments)
	}

	if bi.Infix == "in" {
		// NOTE(sr): `in` requires special handling, mirroring what happens in the parser,
		// since there can be one or two lhs arguments.
		return w.writeInOperator(true, x[1:], comments)
	}

	// TODO(tsandall): improve to consider precedence?
	if parens {
		w.write("(")
	}
	comments = w.writeTermParens(true, x[1], comments)
	w.write(" " + bi.Infix + " ")
	comments = w.writeTermParens(true, x[2], comments)
	if parens {
		w.write(")")
	}

	return comments
}

func (w *writer) writeInOperator(parens bool, operands []*ast.Term, comments []*ast.Comment) []*ast.Comment {
	kw := "in"
	switch len(operands) {
	case 2:
		comments = w.writeTermParens(true, operands[0], comments)
		w.write(" ")
		w.write(kw)
		w.write(" ")
		comments = w.writeTermParens(true, operands[1], comments)
	case 3:
		if parens {
			w.write("(")
			defer w.write(")")
		}
		comments = w.writeTermParens(true, operands[0], comments)
		w.write(", ")
		comments = w.writeTermParens(true, operands[1], comments)
		w.write(" ")
		w.write(kw)
		w.write(" ")
		comments = w.writeTermParens(true, operands[2], comments)
	}
	return comments
}

func (w *writer) writeObject(obj ast.Object, loc *ast.Location, comments []*ast.Comment) []*ast.Comment {
	w.write("{")
	defer w.write("}")

	var s []interface{}
	obj.Foreach(func(k, v *ast.Term) {
		s = append(s, ast.Item(k, v))
	})
	return w.writeIterable(s, loc, closingLoc(0, 0, '{', '}', loc), comments, w.objectWriter())
}

func (w *writer) writeArray(arr *ast.Array, loc *ast.Location, comments []*ast.Comment) []*ast.Comment {
	w.write("[")
	defer w.write("]")

	var s []interface{}
	arr.Foreach(func(t *ast.Term) {
		s = append(s, t)
	})
	return w.writeIterable(s, loc, closingLoc(0, 0, '[', ']', loc), comments, w.listWriter())
}

func (w *writer) writeSet(set ast.Set, loc *ast.Location, comments []*ast.Comment) []*ast.Comment {

	if set.Len() == 0 {
		w.write("set()")
		return w.insertComments(comments, closingLoc(0, 0, '(', ')', loc))
	}

	w.write("{")
	defer w.write("}")

	var s []interface{}
	set.Foreach(func(t *ast.Term) {
		s = append(s, t)
	})
	return w.writeIterable(s, loc, closingLoc(0, 0, '{', '}', loc), comments, w.listWriter())
}

func (w *writer) writeArrayComprehension(arr *ast.ArrayComprehension, loc *ast.Location, comments []*ast.Comment) []*ast.Comment {
	w.write("[")
	defer w.write("]")

	return w.writeComprehension('[', ']', arr.Term, arr.Body, loc, comments)
}

func (w *writer) writeSetComprehension(set *ast.SetComprehension, loc *ast.Location, comments []*ast.Comment) []*ast.Comment {
	w.write("{")
	defer w.write("}")

	return w.writeComprehension('{', '}', set.Term, set.Body, loc, comments)
}

func (w *writer) writeObjectComprehension(object *ast.ObjectComprehension, loc *ast.Location, comments []*ast.Comment) []*ast.Comment {
	w.write("{")
	defer w.write("}")

	object.Value.Location = object.Key.Location // Ensure the value is not written on the next line.
	if object.Key.Location.Row-loc.Row > 1 {
		w.endLine()
		w.startLine()
	}

	comments = w.writeTerm(object.Key, comments)
	w.write(": ")
	return w.writeComprehension('{', '}', object.Value, object.Body, loc, comments)
}

func (w *writer) writeComprehension(open, close byte, term *ast.Term, body ast.Body, loc *ast.Location, comments []*ast.Comment) []*ast.Comment {
	if term.Location.Row-loc.Row > 1 {
		w.endLine()
		w.startLine()
	}

	comments = w.writeTerm(term, comments)
	w.write(" |")

	return w.writeComprehensionBody(open, close, body, term.Location, loc, comments)
}

func (w *writer) writeComprehensionBody(open, close byte, body ast.Body, term, compr *ast.Location, comments []*ast.Comment) []*ast.Comment {
	var exprs []interface{}
	for _, expr := range body {
		exprs = append(exprs, expr)
	}
	lines := groupIterable(exprs, term)

	if body.Loc().Row-term.Row > 0 || len(lines) > 1 {
		w.endLine()
		w.up()
		defer w.startLine()
		defer w.down()

		comments = w.writeBody(body, comments)
	} else {
		w.write(" ")
		i := 0
		for ; i < len(body)-1; i++ {
			comments = w.writeExpr(body[i], comments)
			w.write("; ")
		}
		comments = w.writeExpr(body[i], comments)
	}

	return w.insertComments(comments, closingLoc(0, 0, open, close, compr))
}

func (w *writer) writeImports(imports []*ast.Import, comments []*ast.Comment) []*ast.Comment {
	m, comments := mapImportsToComments(imports, comments)

	groups := groupImports(imports)
	for _, group := range groups {
		comments = w.insertComments(comments, group[0].Loc())

		// Sort imports within a newline grouping.
		sort.Slice(group, func(i, j int) bool {
			a := group[i]
			b := group[j]
			return a.Compare(b) < 0
		})
		for _, i := range group {
			w.startLine()
			w.write(i.String())
			if c, ok := m[i]; ok {
				w.write(" " + c.String())
			}
			w.endLine()
		}
		w.blankLine()
	}

	return comments
}

type entryWriter func(interface{}, []*ast.Comment) []*ast.Comment

func (w *writer) writeIterable(elements []interface{}, last *ast.Location, close *ast.Location, comments []*ast.Comment, fn entryWriter) []*ast.Comment {
	lines := groupIterable(elements, last)
	if len(lines) > 1 {
		w.delayBeforeEnd()
		w.startMultilineSeq()
	}

	i := 0
	for ; i < len(lines)-1; i++ {
		comments = w.writeIterableLine(lines[i], comments, fn)
		w.write(",")

		w.endLine()
		w.startLine()
	}

	comments = w.writeIterableLine(lines[i], comments, fn)

	if len(lines) > 1 {
		w.write(",")
		w.endLine()
		comments = w.insertComments(comments, close)
		w.down()
		w.startLine()
	}

	return comments
}

func (w *writer) writeIterableLine(elements []interface{}, comments []*ast.Comment, fn entryWriter) []*ast.Comment {
	if len(elements) == 0 {
		return comments
	}

	i := 0
	for ; i < len(elements)-1; i++ {
		comments = fn(elements[i], comments)
		w.write(", ")
	}

	return fn(elements[i], comments)
}

func (w *writer) objectWriter() entryWriter {
	return func(x interface{}, comments []*ast.Comment) []*ast.Comment {
		entry := x.([2]*ast.Term)
		comments = w.writeTerm(entry[0], comments)
		w.write(": ")
		return w.writeTerm(entry[1], comments)
	}
}

func (w *writer) listWriter() entryWriter {
	return func(x interface{}, comments []*ast.Comment) []*ast.Comment {
		return w.writeTerm(x.(*ast.Term), comments)
	}
}

// groupIterable will group the `elements` slice into slices according to their
// location: anything on the same line will be put into a slice.
func groupIterable(elements []interface{}, last *ast.Location) [][]interface{} {
	// Generated vars occur in the AST when we're rendering the result of
	// partial evaluation in a bundle build with optimization.
	// Those variables, and wildcard variables have the "default location",
	// set in `Ast()`). That is no proper file location, and the grouping
	// based on source location will yield a bad result.
	// Another case is generated variables: they do have proper file locations,
	// but their row/col information may no longer match their AST location.
	// So, for generated variables, we also don't trust the location, but
	// keep them ungrouped.
	def := false // default location found?
	for _, elem := range elements {
		ast.WalkTerms(elem, func(t *ast.Term) bool {
			if t.Location.File == defaultLocationFile {
				def = true
				return true
			}
			return false
		})
		ast.WalkVars(elem, func(v ast.Var) bool {
			if v.IsGenerated() {
				def = true
				return true
			}
			return false
		})
		if def { // return as-is
			return [][]interface{}{elements}
		}
	}
	sort.Slice(elements, func(i, j int) bool {
		return locLess(elements[i], elements[j])
	})

	var lines [][]interface{}
	var cur []interface{}
	for i, t := range elements {
		elem := t
		loc := getLoc(elem)
		lineDiff := loc.Row - last.Row
		if lineDiff > 0 && i > 0 {
			lines = append(lines, cur)
			cur = nil
		}

		last = loc
		cur = append(cur, elem)
	}
	return append(lines, cur)
}

func mapImportsToComments(imports []*ast.Import, comments []*ast.Comment) (map[*ast.Import]*ast.Comment, []*ast.Comment) {
	var leftovers []*ast.Comment
	m := map[*ast.Import]*ast.Comment{}

	for _, c := range comments {
		matched := false
		for _, i := range imports {
			if c.Loc().Row == i.Loc().Row {
				m[i] = c
				matched = true
				break
			}
		}
		if !matched {
			leftovers = append(leftovers, c)
		}
	}

	return m, leftovers
}

func groupImports(imports []*ast.Import) [][]*ast.Import {
	switch len(imports) { // shortcuts
	case 0:
		return nil
	case 1:
		return [][]*ast.Import{imports}
	}
	// there are >=2 imports to group

	var groups [][]*ast.Import
	group := []*ast.Import{imports[0]}

	for _, i := range imports[1:] {
		last := group[len(group)-1]

		// nil-location imports have been sorted up to come first
		if i.Loc() != nil && last.Loc() != nil && // first import with a location, or
			i.Loc().Row-last.Loc().Row > 1 { // more than one row apart from previous import

			// start a new group
			groups = append(groups, group)
			group = []*ast.Import{}
		}
		group = append(group, i)
	}
	if len(group) > 0 {
		groups = append(groups, group)
	}

	return groups
}

func partitionComments(comments []*ast.Comment, l *ast.Location) (before []*ast.Comment, at *ast.Comment, after []*ast.Comment) {
	for _, c := range comments {
		switch cmp := c.Location.Row - l.Row; {
		case cmp < 0:
			before = append(before, c)
		case cmp > 0:
			after = append(after, c)
		case cmp == 0:
			at = c
		}
	}

	return before, at, after
}

func gatherImports(others []interface{}) (imports []*ast.Import, rest []interface{}) {
	i := 0
loop:
	for ; i < len(others); i++ {
		switch x := others[i].(type) {
		case *ast.Import:
			imports = append(imports, x)
		case *ast.Rule:
			break loop
		}
	}
	return imports, others[i:]
}

func gatherRules(others []interface{}) (rules []*ast.Rule, rest []interface{}) {
	i := 0
loop:
	for ; i < len(others); i++ {
		switch x := others[i].(type) {
		case *ast.Rule:
			rules = append(rules, x)
		case *ast.Import:
			break loop
		}
	}
	return rules, others[i:]
}

func locLess(a, b interface{}) bool {
	return locCmp(a, b) < 0
}

func locCmp(a, b interface{}) int {
	al := getLoc(a)
	bl := getLoc(b)
	switch {
	case al == nil && bl == nil:
		return 0
	case al == nil:
		return -1
	case bl == nil:
		return 1
	}

	if cmp := al.Row - bl.Row; cmp != 0 {
		return cmp

	}
	return al.Col - bl.Col
}

func getLoc(x interface{}) *ast.Location {
	switch x := x.(type) {
	case ast.Node: // *ast.Head, *ast.Expr, *ast.With, *ast.Term
		return x.Loc()
	case *ast.Location:
		return x
	case [2]*ast.Term: // Special case to allow for easy printing of objects.
		return x[0].Location
	default:
		panic("Not reached")
	}
}

func closingLoc(skipOpen, skipClose, open, close byte, loc *ast.Location) *ast.Location {
	i, offset := 0, 0

	// Skip past parens/brackets/braces in rule heads.
	if skipOpen > 0 {
		i, offset = skipPast(skipOpen, skipClose, loc)
	}

	for ; i < len(loc.Text) && loc.Text[i] != open; i++ {
	}

	if i >= len(loc.Text) {
		return &ast.Location{Row: -1}
	}

	state := 1
	for state > 0 {
		i++
		if i >= len(loc.Text) {
			return &ast.Location{Row: -1}
		}

		switch loc.Text[i] {
		case open:
			state++
		case close:
			state--
		case '\n':
			offset++
		}
	}

	return &ast.Location{Row: loc.Row + offset}
}

func skipPast(open, close byte, loc *ast.Location) (int, int) {
	i := 0
	for ; i < len(loc.Text) && loc.Text[i] != open; i++ {
	}

	state := 1
	offset := 0
	for state > 0 {
		i++
		if i >= len(loc.Text) {
			return i, offset
		}

		switch loc.Text[i] {
		case open:
			state++
		case close:
			state--
		case '\n':
			offset++
		}
	}

	return i, offset
}

func dedupComments(comments []*ast.Comment) []*ast.Comment {
	if len(comments) == 0 {
		return nil
	}

	filtered := []*ast.Comment{comments[0]}
	for i := 1; i < len(comments); i++ {
		if comments[i].Location.Equal(comments[i-1].Location) {
			continue
		}
		filtered = append(filtered, comments[i])
	}
	return filtered
}

// startLine begins a line with the current indentation level.
func (w *writer) startLine() {
	w.inline = true
	for i := 0; i < w.level; i++ {
		w.write(w.indent)
	}
}

// endLine ends a line with a newline.
func (w *writer) endLine() {
	w.inline = false
	if w.beforeEnd != nil && !w.delay {
		w.write(" " + w.beforeEnd.String())
		w.beforeEnd = nil
	}
	w.delay = false
	w.write("\n")
}

// beforeLineEnd registers a comment to be printed at the end of the current line.
func (w *writer) beforeLineEnd(c *ast.Comment) {
	if w.beforeEnd != nil {
		if c == nil {
			return
		}
		panic("overwriting non-nil beforeEnd")
	}
	w.beforeEnd = c
}

func (w *writer) delayBeforeEnd() {
	w.delay = true
}

// line prints a blank line. If the writer is currently in the middle of a line,
// line ends it and then prints a blank one.
func (w *writer) blankLine() {
	if w.inline {
		w.endLine()
	}
	w.write("\n")
}

// write the input string and writes it to the buffer.
func (w *writer) write(s string) {
	w.buf.WriteString(s)
}

// writeLine writes the string on a newly started line, then terminate the line.
func (w *writer) writeLine(s string) {
	if !w.inline {
		w.startLine()
	}
	w.write(s)
	w.endLine()
}

func (w *writer) startMultilineSeq() {
	w.endLine()
	w.up()
	w.startLine()
}

// up increases the indentation level
func (w *writer) up() {
	w.level++
}

// down decreases the indentation level
func (w *writer) down() {
	if w.level == 0 {
		panic("negative indentation level")
	}
	w.level--
}

func ensureFutureKeywordImport(imps []*ast.Import, kw string) []*ast.Import {
	allKeywords := ast.MustParseTerm("future.keywords")
	kwPath := ast.MustParseTerm("future.keywords." + kw)
	for _, imp := range imps {
		if allKeywords.Equal(imp.Path) || imp.Path.Equal(kwPath) {
			return imps
		}
	}
	return append(imps, &ast.Import{Path: kwPath})
}
