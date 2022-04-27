// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// This file contains extra functions for parsing Rego.
// Most of the parsing is handled by the code in parser.go,
// however, there are additional utilities that are
// helpful for dealing with Rego source inputs (e.g., REPL
// statements, source files, etc.)

package ast

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"

	"github.com/pkg/errors"
)

// MustParseBody returns a parsed body.
// If an error occurs during parsing, panic.
func MustParseBody(input string) Body {
	return MustParseBodyWithOpts(input, ParserOptions{})
}

// MustParseBodyWithOpts returns a parsed body.
// If an error occurs during parsing, panic.
func MustParseBodyWithOpts(input string, opts ParserOptions) Body {
	parsed, err := ParseBodyWithOpts(input, opts)
	if err != nil {
		panic(err)
	}
	return parsed
}

// MustParseExpr returns a parsed expression.
// If an error occurs during parsing, panic.
func MustParseExpr(input string) *Expr {
	parsed, err := ParseExpr(input)
	if err != nil {
		panic(err)
	}
	return parsed
}

// MustParseImports returns a slice of imports.
// If an error occurs during parsing, panic.
func MustParseImports(input string) []*Import {
	parsed, err := ParseImports(input)
	if err != nil {
		panic(err)
	}
	return parsed
}

// MustParseModule returns a parsed module.
// If an error occurs during parsing, panic.
func MustParseModule(input string) *Module {
	return MustParseModuleWithOpts(input, ParserOptions{})
}

// MustParseModuleWithOpts returns a parsed module.
// If an error occurs during parsing, panic.
func MustParseModuleWithOpts(input string, opts ParserOptions) *Module {
	parsed, err := ParseModuleWithOpts("", input, opts)
	if err != nil {
		panic(err)
	}
	return parsed
}

// MustParsePackage returns a Package.
// If an error occurs during parsing, panic.
func MustParsePackage(input string) *Package {
	parsed, err := ParsePackage(input)
	if err != nil {
		panic(err)
	}
	return parsed
}

// MustParseStatements returns a slice of parsed statements.
// If an error occurs during parsing, panic.
func MustParseStatements(input string) []Statement {
	parsed, _, err := ParseStatements("", input)
	if err != nil {
		panic(err)
	}
	return parsed
}

// MustParseStatement returns exactly one statement.
// If an error occurs during parsing, panic.
func MustParseStatement(input string) Statement {
	parsed, err := ParseStatement(input)
	if err != nil {
		panic(err)
	}
	return parsed
}

// MustParseRef returns a parsed reference.
// If an error occurs during parsing, panic.
func MustParseRef(input string) Ref {
	parsed, err := ParseRef(input)
	if err != nil {
		panic(err)
	}
	return parsed
}

// MustParseRule returns a parsed rule.
// If an error occurs during parsing, panic.
func MustParseRule(input string) *Rule {
	parsed, err := ParseRule(input)
	if err != nil {
		panic(err)
	}
	return parsed
}

// MustParseTerm returns a parsed term.
// If an error occurs during parsing, panic.
func MustParseTerm(input string) *Term {
	parsed, err := ParseTerm(input)
	if err != nil {
		panic(err)
	}
	return parsed
}

// ParseRuleFromBody returns a rule if the body can be interpreted as a rule
// definition. Otherwise, an error is returned.
func ParseRuleFromBody(module *Module, body Body) (*Rule, error) {

	if len(body) != 1 {
		return nil, fmt.Errorf("multiple expressions cannot be used for rule head")
	}

	return ParseRuleFromExpr(module, body[0])
}

// ParseRuleFromExpr returns a rule if the expression can be interpreted as a
// rule definition.
func ParseRuleFromExpr(module *Module, expr *Expr) (*Rule, error) {

	if len(expr.With) > 0 {
		return nil, fmt.Errorf("expressions using with keyword cannot be used for rule head")
	}

	if expr.Negated {
		return nil, fmt.Errorf("negated expressions cannot be used for rule head")
	}

	if _, ok := expr.Terms.(*SomeDecl); ok {
		return nil, errors.New("some declarations cannot be used for rule head")
	}

	if term, ok := expr.Terms.(*Term); ok {
		switch v := term.Value.(type) {
		case Ref:
			return ParsePartialSetDocRuleFromTerm(module, term)
		default:
			return nil, fmt.Errorf("%v cannot be used for rule name", TypeName(v))
		}
	}

	if _, ok := expr.Terms.([]*Term); !ok {
		// This is a defensive check in case other kinds of expression terms are
		// introduced in the future.
		return nil, errors.New("expression cannot be used for rule head")
	}

	if expr.IsAssignment() {

		lhs, rhs := expr.Operand(0), expr.Operand(1)
		if lhs == nil || rhs == nil {
			return nil, errors.New("assignment requires two operands")
		}

		rule, err := ParseCompleteDocRuleFromAssignmentExpr(module, lhs, rhs)

		if err == nil {
			rule.Location = expr.Location
			rule.Head.Location = expr.Location
			return rule, nil
		} else if _, ok := lhs.Value.(Call); ok {
			return nil, errFunctionAssignOperator
		} else if _, ok := lhs.Value.(Ref); ok {
			return nil, errPartialRuleAssignOperator
		}

		return nil, errTermAssignOperator(lhs.Value)
	}

	if expr.IsEquality() {
		return parseCompleteRuleFromEq(module, expr)
	}

	if _, ok := BuiltinMap[expr.Operator().String()]; ok {
		return nil, fmt.Errorf("rule name conflicts with built-in function")
	}

	return ParseRuleFromCallExpr(module, expr.Terms.([]*Term))
}

func parseCompleteRuleFromEq(module *Module, expr *Expr) (rule *Rule, err error) {

	// ensure the rule location is set to the expr location
	// the helper functions called below try to set the location based
	// on the terms they've been provided but that is not as accurate.
	defer func() {
		if rule != nil {
			rule.Location = expr.Location
			rule.Head.Location = expr.Location
		}
	}()

	lhs, rhs := expr.Operand(0), expr.Operand(1)
	if lhs == nil || rhs == nil {
		return nil, errors.New("assignment requires two operands")
	}

	rule, err = ParseCompleteDocRuleFromEqExpr(module, lhs, rhs)

	if err == nil {
		return rule, nil
	}

	rule, err = ParseRuleFromCallEqExpr(module, lhs, rhs)
	if err == nil {
		return rule, nil
	}

	return ParsePartialObjectDocRuleFromEqExpr(module, lhs, rhs)
}

// ParseCompleteDocRuleFromAssignmentExpr returns a rule if the expression can
// be interpreted as a complete document definition declared with the assignment
// operator.
func ParseCompleteDocRuleFromAssignmentExpr(module *Module, lhs, rhs *Term) (*Rule, error) {

	rule, err := ParseCompleteDocRuleFromEqExpr(module, lhs, rhs)
	if err != nil {
		return nil, err
	}

	rule.Head.Assign = true

	return rule, nil
}

// ParseCompleteDocRuleFromEqExpr returns a rule if the expression can be
// interpreted as a complete document definition.
func ParseCompleteDocRuleFromEqExpr(module *Module, lhs, rhs *Term) (*Rule, error) {

	var name Var

	if RootDocumentRefs.Contains(lhs) {
		name = lhs.Value.(Ref)[0].Value.(Var)
	} else if v, ok := lhs.Value.(Var); ok {
		name = v
	} else {
		return nil, fmt.Errorf("%v cannot be used for rule name", TypeName(lhs.Value))
	}

	rule := &Rule{
		Location: lhs.Location,
		Head: &Head{
			Location: lhs.Location,
			Name:     name,
			Value:    rhs,
		},
		Body: NewBody(
			NewExpr(BooleanTerm(true).SetLocation(rhs.Location)).SetLocation(rhs.Location),
		),
		Module: module,
	}

	return rule, nil
}

// ParsePartialObjectDocRuleFromEqExpr returns a rule if the expression can be
// interpreted as a partial object document definition.
func ParsePartialObjectDocRuleFromEqExpr(module *Module, lhs, rhs *Term) (*Rule, error) {

	ref, ok := lhs.Value.(Ref)
	if !ok || len(ref) != 2 {
		return nil, fmt.Errorf("%v cannot be used as rule name", TypeName(lhs.Value))
	}

	if _, ok := ref[0].Value.(Var); !ok {
		return nil, fmt.Errorf("%vs cannot be used as rule name", TypeName(ref[0].Value))
	}

	name := ref[0].Value.(Var)
	key := ref[1]

	rule := &Rule{
		Location: rhs.Location,
		Head: &Head{
			Location: rhs.Location,
			Name:     name,
			Key:      key,
			Value:    rhs,
		},
		Body: NewBody(
			NewExpr(BooleanTerm(true).SetLocation(rhs.Location)).SetLocation(rhs.Location),
		),
		Module: module,
	}

	return rule, nil
}

// ParsePartialSetDocRuleFromTerm returns a rule if the term can be interpreted
// as a partial set document definition.
func ParsePartialSetDocRuleFromTerm(module *Module, term *Term) (*Rule, error) {

	ref, ok := term.Value.(Ref)
	if !ok {
		return nil, fmt.Errorf("%vs cannot be used for rule head", TypeName(term.Value))
	}

	if len(ref) != 2 {
		return nil, fmt.Errorf("refs cannot be used for rule")
	}

	name, ok := ref[0].Value.(Var)
	if !ok {
		return nil, fmt.Errorf("%vs cannot be used as rule name", TypeName(ref[0].Value))
	}

	rule := &Rule{
		Location: term.Location,
		Head: &Head{
			Location: term.Location,
			Name:     name,
			Key:      ref[1],
		},
		Body: NewBody(
			NewExpr(BooleanTerm(true).SetLocation(term.Location)).SetLocation(term.Location),
		),
		Module: module,
	}

	return rule, nil
}

// ParseRuleFromCallEqExpr returns a rule if the term can be interpreted as a
// function definition (e.g., f(x) = y => f(x) = y { true }).
func ParseRuleFromCallEqExpr(module *Module, lhs, rhs *Term) (*Rule, error) {

	call, ok := lhs.Value.(Call)
	if !ok {
		return nil, fmt.Errorf("must be call")
	}

	ref, ok := call[0].Value.(Ref)
	if !ok {
		return nil, fmt.Errorf("%vs cannot be used in function signature", TypeName(call[0].Value))
	}

	name, ok := ref[0].Value.(Var)
	if !ok {
		return nil, fmt.Errorf("%vs cannot be used in function signature", TypeName(ref[0].Value))
	}

	rule := &Rule{
		Location: lhs.Location,
		Head: &Head{
			Location: lhs.Location,
			Name:     name,
			Args:     Args(call[1:]),
			Value:    rhs,
		},
		Body:   NewBody(NewExpr(BooleanTerm(true).SetLocation(rhs.Location)).SetLocation(rhs.Location)),
		Module: module,
	}

	return rule, nil
}

// ParseRuleFromCallExpr returns a rule if the terms can be interpreted as a
// function returning true or some value (e.g., f(x) => f(x) = true { true }).
func ParseRuleFromCallExpr(module *Module, terms []*Term) (*Rule, error) {

	if len(terms) <= 1 {
		return nil, fmt.Errorf("rule argument list must take at least one argument")
	}

	loc := terms[0].Location
	args := terms[1:]
	value := BooleanTerm(true).SetLocation(loc)

	rule := &Rule{
		Location: loc,
		Head: &Head{
			Location: loc,
			Name:     Var(terms[0].String()),
			Args:     args,
			Value:    value,
		},
		Module: module,
		Body:   NewBody(NewExpr(BooleanTerm(true).SetLocation(loc)).SetLocation(loc)),
	}
	return rule, nil
}

// ParseImports returns a slice of Import objects.
func ParseImports(input string) ([]*Import, error) {
	stmts, _, err := ParseStatements("", input)
	if err != nil {
		return nil, err
	}
	result := []*Import{}
	for _, stmt := range stmts {
		if imp, ok := stmt.(*Import); ok {
			result = append(result, imp)
		} else {
			return nil, fmt.Errorf("expected import but got %T", stmt)
		}
	}
	return result, nil
}

// ParseModule returns a parsed Module object.
// For details on Module objects and their fields, see policy.go.
// Empty input will return nil, nil.
func ParseModule(filename, input string) (*Module, error) {
	return ParseModuleWithOpts(filename, input, ParserOptions{})
}

// ParseModuleWithOpts returns a parsed Module object, and has an additional input ParserOptions
// For details on Module objects and their fields, see policy.go.
// Empty input will return nil, nil.
func ParseModuleWithOpts(filename, input string, popts ParserOptions) (*Module, error) {
	stmts, comments, err := ParseStatementsWithOpts(filename, input, popts)
	if err != nil {
		return nil, err
	}
	return parseModule(filename, stmts, comments)
}

// ParseBody returns exactly one body.
// If multiple bodies are parsed, an error is returned.
func ParseBody(input string) (Body, error) {
	return ParseBodyWithOpts(input, ParserOptions{})
}

func ParseBodyWithOpts(input string, popts ParserOptions) (Body, error) {
	stmts, _, err := ParseStatementsWithOpts("", input, popts)
	if err != nil {
		return nil, err
	}

	result := Body{}

	for _, stmt := range stmts {
		switch stmt := stmt.(type) {
		case Body:
			for i := range stmt {
				result.Append(stmt[i])
			}
		case *Comment:
			// skip
		default:
			return nil, fmt.Errorf("expected body but got %T", stmt)
		}
	}

	return result, nil
}

// ParseExpr returns exactly one expression.
// If multiple expressions are parsed, an error is returned.
func ParseExpr(input string) (*Expr, error) {
	body, err := ParseBody(input)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse expression")
	}
	if len(body) != 1 {
		return nil, fmt.Errorf("expected exactly one expression but got: %v", body)
	}
	return body[0], nil
}

// ParsePackage returns exactly one Package.
// If multiple statements are parsed, an error is returned.
func ParsePackage(input string) (*Package, error) {
	stmt, err := ParseStatement(input)
	if err != nil {
		return nil, err
	}
	pkg, ok := stmt.(*Package)
	if !ok {
		return nil, fmt.Errorf("expected package but got %T", stmt)
	}
	return pkg, nil
}

// ParseTerm returns exactly one term.
// If multiple terms are parsed, an error is returned.
func ParseTerm(input string) (*Term, error) {
	body, err := ParseBody(input)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse term")
	}
	if len(body) != 1 {
		return nil, fmt.Errorf("expected exactly one term but got: %v", body)
	}
	term, ok := body[0].Terms.(*Term)
	if !ok {
		return nil, fmt.Errorf("expected term but got %v", body[0].Terms)
	}
	return term, nil
}

// ParseRef returns exactly one reference.
func ParseRef(input string) (Ref, error) {
	term, err := ParseTerm(input)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse ref")
	}
	ref, ok := term.Value.(Ref)
	if !ok {
		return nil, fmt.Errorf("expected ref but got %v", term)
	}
	return ref, nil
}

// ParseRule returns exactly one rule.
// If multiple rules are parsed, an error is returned.
func ParseRule(input string) (*Rule, error) {
	stmts, _, err := ParseStatements("", input)
	if err != nil {
		return nil, err
	}
	if len(stmts) != 1 {
		return nil, fmt.Errorf("expected exactly one statement (rule)")
	}
	rule, ok := stmts[0].(*Rule)
	if !ok {
		return nil, fmt.Errorf("expected rule but got %T", stmts[0])
	}
	return rule, nil
}

// ParseStatement returns exactly one statement.
// A statement might be a term, expression, rule, etc. Regardless,
// this function expects *exactly* one statement. If multiple
// statements are parsed, an error is returned.
func ParseStatement(input string) (Statement, error) {
	stmts, _, err := ParseStatements("", input)
	if err != nil {
		return nil, err
	}
	if len(stmts) != 1 {
		return nil, fmt.Errorf("expected exactly one statement")
	}
	return stmts[0], nil
}

// ParseStatements is deprecated. Use ParseStatementWithOpts instead.
func ParseStatements(filename, input string) ([]Statement, []*Comment, error) {
	return ParseStatementsWithOpts(filename, input, ParserOptions{})
}

// ParseStatementsWithOpts returns a slice of parsed statements. This is the
// default return value from the parser.
func ParseStatementsWithOpts(filename, input string, popts ParserOptions) ([]Statement, []*Comment, error) {

	parser := NewParser().
		WithFilename(filename).
		WithReader(bytes.NewBufferString(input)).
		WithProcessAnnotation(popts.ProcessAnnotation).
		WithFutureKeywords(popts.FutureKeywords...).
		WithAllFutureKeywords(popts.AllFutureKeywords).
		WithCapabilities(popts.Capabilities).
		withUnreleasedKeywords(popts.unreleasedKeywords)

	stmts, comments, errs := parser.Parse()

	if len(errs) > 0 {
		return nil, nil, errs
	}

	return stmts, comments, nil
}

func parseModule(filename string, stmts []Statement, comments []*Comment) (*Module, error) {

	if len(stmts) == 0 {
		return nil, NewError(ParseErr, &Location{File: filename}, "empty module")
	}

	var errs Errors

	_package, ok := stmts[0].(*Package)
	if !ok {
		loc := stmts[0].Loc()
		errs = append(errs, NewError(ParseErr, loc, "package expected"))
	}

	mod := &Module{
		Package: _package,
	}

	// The comments slice only holds comments that were not their own statements.
	mod.Comments = append(mod.Comments, comments...)

	for i, stmt := range stmts[1:] {
		switch stmt := stmt.(type) {
		case *Import:
			mod.Imports = append(mod.Imports, stmt)
		case *Rule:
			setRuleModule(stmt, mod)
			mod.Rules = append(mod.Rules, stmt)
		case Body:
			rule, err := ParseRuleFromBody(mod, stmt)
			if err != nil {
				errs = append(errs, NewError(ParseErr, stmt[0].Location, err.Error()))
			} else {
				mod.Rules = append(mod.Rules, rule)

				// NOTE(tsandall): the statement should now be interpreted as a
				// rule so update the statement list. This is important for the
				// logic below that associates annotations with statements.
				stmts[i+1] = rule
			}
		case *Package:
			errs = append(errs, NewError(ParseErr, stmt.Loc(), "unexpected package"))
		case *Annotations:
			mod.Annotations = append(mod.Annotations, stmt)
		case *Comment:
			// Ignore comments, they're handled above.
		default:
			panic("illegal value") // Indicates grammar is out-of-sync with code.
		}
	}

	if len(errs) > 0 {
		return nil, errs
	}

	// Find first non-annotation statement following each annotation and attach
	// the annotation to that statement.
	for _, a := range mod.Annotations {
		for _, stmt := range stmts {
			_, ok := stmt.(*Annotations)
			if !ok {
				if stmt.Loc().Row > a.Location.Row {
					a.node = stmt
					break
				}
			}
		}

		if a.Scope == "" {
			switch a.node.(type) {
			case *Rule:
				a.Scope = annotationScopeRule
			case *Package:
				a.Scope = annotationScopePackage
			case *Import:
				a.Scope = annotationScopeImport
			}
		}

		if err := validateAnnotationScopeAttachment(a); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return nil, errs
	}

	return mod, nil
}

func validateAnnotationScopeAttachment(a *Annotations) *Error {

	switch a.Scope {
	case annotationScopeRule, annotationScopeDocument:
		if _, ok := a.node.(*Rule); ok {
			return nil
		}
		return newScopeAttachmentErr(a, "rule")
	case annotationScopePackage, annotationScopeSubpackages:
		if _, ok := a.node.(*Package); ok {
			return nil
		}
		return newScopeAttachmentErr(a, "package")
	}

	return NewError(ParseErr, a.Loc(), "invalid annotation scope '%v'", a.Scope)
}

func newScopeAttachmentErr(a *Annotations, want string) *Error {
	var have string
	if a.node != nil {
		have = fmt.Sprintf(" (have %v)", TypeName(a.node))
	}
	return NewError(ParseErr, a.Loc(), "annotation scope '%v' must be applied to %v%v", a.Scope, want, have)
}

func setRuleModule(rule *Rule, module *Module) {
	rule.Module = module
	if rule.Else != nil {
		setRuleModule(rule.Else, module)
	}
}

// ParserErrorDetail holds additional details for parser errors.
type ParserErrorDetail struct {
	Line string `json:"line"`
	Idx  int    `json:"idx"`
}

func newParserErrorDetail(bs []byte, offset int) *ParserErrorDetail {

	// Find first non-space character at or before offset position.
	if offset >= len(bs) {
		offset = len(bs) - 1
	} else if offset < 0 {
		offset = 0
	}

	for offset > 0 && unicode.IsSpace(rune(bs[offset])) {
		offset--
	}

	// Find beginning of line containing offset.
	begin := offset

	for begin > 0 && !isNewLineChar(bs[begin]) {
		begin--
	}

	if isNewLineChar(bs[begin]) {
		begin++
	}

	// Find end of line containing offset.
	end := offset

	for end < len(bs) && !isNewLineChar(bs[end]) {
		end++
	}

	if begin > end {
		begin = end
	}

	// Extract line and compute index of offset byte in line.
	line := bs[begin:end]
	index := offset - begin

	return &ParserErrorDetail{
		Line: string(line),
		Idx:  index,
	}
}

// Lines returns the pretty formatted line output for the error details.
func (d ParserErrorDetail) Lines() []string {
	line := strings.TrimLeft(d.Line, "\t") // remove leading tabs
	tabCount := len(d.Line) - len(line)
	indent := d.Idx - tabCount
	if indent < 0 {
		indent = 0
	}
	return []string{line, strings.Repeat(" ", indent) + "^"}
}

func isNewLineChar(b byte) bool {
	return b == '\r' || b == '\n'
}
