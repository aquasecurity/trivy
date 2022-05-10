// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/open-policy-agent/opa/ast/internal/scanner"
	"github.com/open-policy-agent/opa/ast/internal/tokens"
	"github.com/open-policy-agent/opa/ast/location"
)

// Note: This state is kept isolated from the parser so that we
// can do efficient shallow copies of these values when doing a
// save() and restore().
type state struct {
	s         *scanner.Scanner
	lastEnd   int
	skippedNL bool
	tok       tokens.Token
	tokEnd    int
	lit       string
	loc       Location
	errors    Errors
	hints     []string
	comments  []*Comment
	wildcard  int
}

func (s *state) String() string {
	return fmt.Sprintf("<s: %v, tok: %v, lit: %q, loc: %v, errors: %d, comments: %d>", s.s, s.tok, s.lit, s.loc, len(s.errors), len(s.comments))
}

func (s *state) Loc() *location.Location {
	cpy := s.loc
	return &cpy
}

func (s *state) Text(offset, end int) []byte {
	bs := s.s.Bytes()
	if offset >= 0 && offset < len(bs) {
		if end >= offset && end <= len(bs) {
			return bs[offset:end]
		}
	}
	return nil
}

// Parser is used to parse Rego statements.
type Parser struct {
	r     io.Reader
	s     *state
	po    ParserOptions
	cache parsedTermCache
}

type parsedTermCacheItem struct {
	t      *Term
	post   *state // post is the post-state that's restored on a cache-hit
	offset int
	next   *parsedTermCacheItem
}

type parsedTermCache struct {
	m *parsedTermCacheItem
}

func (c parsedTermCache) String() string {
	s := strings.Builder{}
	s.WriteRune('{')
	var e *parsedTermCacheItem
	for e = c.m; e != nil; e = e.next {
		fmt.Fprintf(&s, "%v", e)
	}
	s.WriteRune('}')
	return s.String()
}

func (e *parsedTermCacheItem) String() string {
	return fmt.Sprintf("<%d:%v>", e.offset, e.t)
}

// ParserOptions defines the options for parsing Rego statements.
type ParserOptions struct {
	Capabilities       *Capabilities
	ProcessAnnotation  bool
	AllFutureKeywords  bool
	FutureKeywords     []string
	unreleasedKeywords bool
}

// NewParser creates and initializes a Parser.
func NewParser() *Parser {
	p := &Parser{
		s:  &state{},
		po: ParserOptions{},
	}
	return p
}

// WithFilename provides the filename for Location details
// on parsed statements.
func (p *Parser) WithFilename(filename string) *Parser {
	p.s.loc.File = filename
	return p
}

// WithReader provides the io.Reader that the parser will
// use as its source.
func (p *Parser) WithReader(r io.Reader) *Parser {
	p.r = r
	return p
}

// WithProcessAnnotation enables or disables the processing of
// annotations by the Parser
func (p *Parser) WithProcessAnnotation(processAnnotation bool) *Parser {
	p.po.ProcessAnnotation = processAnnotation
	return p
}

// WithFutureKeywords enables "future" keywords, i.e., keywords that can
// be imported via
//
//     import future.keywords.kw
//     import future.keywords.other
//
// but in a more direct way. The equivalent of this import would be
//
//     WithFutureKeywords("kw", "other")
func (p *Parser) WithFutureKeywords(kws ...string) *Parser {
	p.po.FutureKeywords = kws
	return p
}

// WithAllFutureKeywords enables all "future" keywords, i.e., the
// ParserOption equivalent of
//
//     import future.keywords
func (p *Parser) WithAllFutureKeywords(yes bool) *Parser {
	p.po.AllFutureKeywords = yes
	return p
}

// withUnreleasedKeywords allows using keywords that haven't surfaced
// as future keywords (see above) yet, but have tests that require
// them to be parsed
func (p *Parser) withUnreleasedKeywords(yes bool) *Parser {
	p.po.unreleasedKeywords = yes
	return p
}

// WithCapabilities sets the capabilities structure on the parser.
func (p *Parser) WithCapabilities(c *Capabilities) *Parser {
	p.po.Capabilities = c
	return p
}

const (
	annotationScopePackage     = "package"
	annotationScopeImport      = "import"
	annotationScopeRule        = "rule"
	annotationScopeDocument    = "document"
	annotationScopeSubpackages = "subpackages"
)

func (p *Parser) parsedTermCacheLookup() (*Term, *state) {
	l := p.s.loc.Offset
	// stop comparing once the cached offsets are lower than l
	for h := p.cache.m; h != nil && h.offset >= l; h = h.next {
		if h.offset == l {
			return h.t, h.post
		}
	}
	return nil, nil
}

func (p *Parser) parsedTermCachePush(t *Term, s0 *state) {
	s1 := p.save()
	o0 := s0.loc.Offset
	entry := parsedTermCacheItem{t: t, post: s1, offset: o0}

	// find the first one whose offset is smaller than ours
	var e *parsedTermCacheItem
	for e = p.cache.m; e != nil; e = e.next {
		if e.offset < o0 {
			break
		}
	}
	entry.next = e
	p.cache.m = &entry
}

// futureParser returns a shallow copy of `p` with an empty
// cache, and a scanner that knows all future keywords.
// It's used to present hints in errors, when statements would
// only parse successfully if some future keyword is enabled.
func (p *Parser) futureParser() *Parser {
	q := *p
	q.s = p.save()
	q.s.s = p.s.s.WithKeywords(futureKeywords)
	q.cache = parsedTermCache{}
	return &q
}

// presentParser returns a shallow copy of `p` with an empty
// cache, and a scanner that knows none of the future keywords.
// It is used to successfully parse keyword imports, like
//
//  import future.keywords.in
//
// even when the parser has already been informed about the
// future keyword "in". This parser won't error out because
// "in" is an identifier.
func (p *Parser) presentParser() (*Parser, map[string]tokens.Token) {
	var cpy map[string]tokens.Token
	q := *p
	q.s = p.save()
	q.s.s, cpy = p.s.s.WithoutKeywords(futureKeywords)
	q.cache = parsedTermCache{}
	return &q, cpy
}

// Parse will read the Rego source and parse statements and
// comments as they are found. Any errors encountered while
// parsing will be accumulated and returned as a list of Errors.
func (p *Parser) Parse() ([]Statement, []*Comment, Errors) {

	if p.po.Capabilities == nil {
		p.po.Capabilities = CapabilitiesForThisVersion()
	}

	allowedFutureKeywords := map[string]tokens.Token{}

	for _, kw := range p.po.Capabilities.FutureKeywords {
		var ok bool
		allowedFutureKeywords[kw], ok = futureKeywords[kw]
		if !ok {
			return nil, nil, Errors{
				&Error{
					Code:     ParseErr,
					Message:  fmt.Sprintf("illegal capabilities: unknown keyword: %v", kw),
					Location: nil,
				},
			}
		}
	}

	if p.po.unreleasedKeywords { // TODO(sr): remove when capabilities include "every"
		allowedFutureKeywords["every"] = tokens.Every
	}

	var err error
	p.s.s, err = scanner.New(p.r)
	if err != nil {
		return nil, nil, Errors{
			&Error{
				Code:     ParseErr,
				Message:  err.Error(),
				Location: nil,
			},
		}
	}

	selected := map[string]tokens.Token{}
	if p.po.AllFutureKeywords {
		for kw, tok := range allowedFutureKeywords {
			selected[kw] = tok
		}
	} else {
		for _, kw := range p.po.FutureKeywords {
			tok, ok := allowedFutureKeywords[kw]
			if !ok {
				return nil, nil, Errors{
					&Error{
						Code:     ParseErr,
						Message:  fmt.Sprintf("unknown future keyword: %v", kw),
						Location: nil,
					},
				}
			}
			selected[kw] = tok
		}
	}
	p.s.s = p.s.s.WithKeywords(selected)

	// read the first token to initialize the parser
	p.scan()

	var stmts []Statement

	// Read from the scanner until the last token is reached or no statements
	// can be parsed. Attempt to parse package statements, import statements,
	// rule statements, and then body/query statements (in that order). If a
	// statement cannot be parsed, restore the parser state before trying the
	// next type of statement. If a statement can be parsed, continue from that
	// point trying to parse packages, imports, etc. in the same order.
	for p.s.tok != tokens.EOF {

		s := p.save()

		if pkg := p.parsePackage(); pkg != nil {
			stmts = append(stmts, pkg)
			continue
		} else if len(p.s.errors) > 0 {
			break
		}

		p.restore(s)
		s = p.save()

		if imp := p.parseImport(); imp != nil {
			if FutureRootDocument.Equal(imp.Path.Value.(Ref)[0]) {
				p.futureImport(imp, allowedFutureKeywords)
			}
			stmts = append(stmts, imp)
			continue
		} else if len(p.s.errors) > 0 {
			break
		}

		p.restore(s)
		s = p.save()

		if rules := p.parseRules(); rules != nil {
			for i := range rules {
				stmts = append(stmts, rules[i])
			}
			continue
		} else if len(p.s.errors) > 0 {
			break
		}

		p.restore(s)

		if body := p.parseQuery(true, tokens.EOF); body != nil {
			stmts = append(stmts, body)
			continue
		}

		break
	}

	if p.po.ProcessAnnotation {
		stmts = p.parseAnnotations(stmts)
	}

	return stmts, p.s.comments, p.s.errors
}

func (p *Parser) parseAnnotations(stmts []Statement) []Statement {

	var hint = []byte("METADATA")
	var curr *metadataParser
	var blocks []*metadataParser

	for i := 0; i < len(p.s.comments); i++ {
		if curr != nil {
			if p.s.comments[i].Location.Row == p.s.comments[i-1].Location.Row+1 && p.s.comments[i].Location.Col == 1 {
				curr.Append(p.s.comments[i])
				continue
			}
			curr = nil
		}
		if bytes.HasPrefix(bytes.TrimSpace(p.s.comments[i].Text), hint) {
			curr = newMetadataParser(p.s.comments[i].Location)
			blocks = append(blocks, curr)
		}
	}

	for _, b := range blocks {
		a, err := b.Parse()
		if err != nil {
			p.error(b.loc, err.Error())
		} else {
			stmts = append(stmts, a)
		}
	}

	return stmts
}

func (p *Parser) parsePackage() *Package {

	var pkg Package
	pkg.SetLoc(p.s.Loc())

	if p.s.tok != tokens.Package {
		return nil
	}

	p.scan()
	if p.s.tok != tokens.Ident {
		p.illegalToken()
		return nil
	}

	term := p.parseTerm()

	if term != nil {
		switch v := term.Value.(type) {
		case Var:
			pkg.Path = Ref{
				DefaultRootDocument.Copy().SetLocation(term.Location),
				StringTerm(string(v)).SetLocation(term.Location),
			}
		case Ref:
			pkg.Path = make(Ref, len(v)+1)
			pkg.Path[0] = DefaultRootDocument.Copy().SetLocation(v[0].Location)
			first, ok := v[0].Value.(Var)
			if !ok {
				p.errorf(v[0].Location, "unexpected %v token: expecting var", TypeName(v[0].Value))
				return nil
			}
			pkg.Path[1] = StringTerm(string(first)).SetLocation(v[0].Location)
			for i := 2; i < len(pkg.Path); i++ {
				switch v[i-1].Value.(type) {
				case String:
					pkg.Path[i] = v[i-1]
				default:
					p.errorf(v[i-1].Location, "unexpected %v token: expecting string", TypeName(v[i-1].Value))
					return nil
				}
			}
		default:
			p.illegalToken()
			return nil
		}
	}

	if pkg.Path == nil {
		if len(p.s.errors) == 0 {
			p.error(p.s.Loc(), "expected path")
		}
		return nil
	}

	return &pkg
}

func (p *Parser) parseImport() *Import {

	var imp Import
	imp.SetLoc(p.s.Loc())

	if p.s.tok != tokens.Import {
		return nil
	}

	p.scan()
	if p.s.tok != tokens.Ident {
		p.error(p.s.Loc(), "expected ident")
		return nil
	}
	q, prev := p.presentParser()
	term := q.parseTerm()
	if term != nil {
		switch v := term.Value.(type) {
		case Var:
			imp.Path = RefTerm(term).SetLocation(term.Location)
		case Ref:
			for i := 1; i < len(v); i++ {
				if _, ok := v[i].Value.(String); !ok {
					p.errorf(v[i].Location, "unexpected %v token: expecting string", TypeName(v[i].Value))
					return nil
				}
			}
			imp.Path = term
		}
	}
	// keep advanced parser state, reset known keywords
	p.s = q.s
	p.s.s = q.s.s.WithKeywords(prev)

	if imp.Path == nil {
		p.error(p.s.Loc(), "expected path")
		return nil
	}

	path := imp.Path.Value.(Ref)

	if !RootDocumentNames.Contains(path[0]) && !FutureRootDocument.Equal(path[0]) {
		p.errorf(imp.Path.Location, "unexpected import path, must begin with one of: %v, got: %v",
			RootDocumentNames.Union(NewSet(FutureRootDocument)),
			path[0])
		return nil
	}

	if p.s.tok == tokens.As {
		p.scan()

		if p.s.tok != tokens.Ident {
			p.illegal("expected var")
			return nil
		}

		if alias := p.parseTerm(); alias != nil {
			v, ok := alias.Value.(Var)
			if ok {
				imp.Alias = v
				return &imp
			}
		}
		p.illegal("expected var")
		return nil
	}

	return &imp
}

func (p *Parser) parseRules() []*Rule {

	var rule Rule
	rule.SetLoc(p.s.Loc())

	if p.s.tok == tokens.Default {
		p.scan()
		rule.Default = true
	}

	if p.s.tok != tokens.Ident {
		return nil
	}

	if rule.Head = p.parseHead(rule.Default); rule.Head == nil {
		return nil
	}

	if rule.Default {
		if !p.validateDefaultRuleValue(&rule) {
			return nil
		}

		rule.Body = NewBody(NewExpr(BooleanTerm(true).SetLocation(rule.Location)).SetLocation(rule.Location))
		return []*Rule{&rule}
	}

	if p.s.tok == tokens.LBrace {
		p.scan()
		if rule.Body = p.parseBody(tokens.RBrace); rule.Body == nil {
			return nil
		}
		p.scan()
	} else {
		return nil
	}

	if p.s.tok == tokens.Else {

		if rule.Head.Assign {
			p.error(p.s.Loc(), "else keyword cannot be used on rule declared with := operator")
			return nil
		}

		if rule.Head.Key != nil {
			p.error(p.s.Loc(), "else keyword cannot be used on partial rules")
			return nil
		}

		if rule.Else = p.parseElse(rule.Head); rule.Else == nil {
			return nil
		}
	}

	rule.Location.Text = p.s.Text(rule.Location.Offset, p.s.lastEnd)

	var rules []*Rule

	rules = append(rules, &rule)

	for p.s.tok == tokens.LBrace {

		if rule.Else != nil {
			p.error(p.s.Loc(), "expected else keyword")
			return nil
		}

		loc := p.s.Loc()

		p.scan()
		var next Rule

		if next.Body = p.parseBody(tokens.RBrace); next.Body == nil {
			return nil
		}
		p.scan()

		loc.Text = p.s.Text(loc.Offset, p.s.lastEnd)
		next.SetLoc(loc)

		// Chained rule head's keep the original
		// rule's head AST but have their location
		// set to the rule body.
		next.Head = rule.Head.Copy()
		setLocRecursive(next.Head, loc)

		rules = append(rules, &next)
	}

	return rules
}

func (p *Parser) parseElse(head *Head) *Rule {

	var rule Rule
	rule.SetLoc(p.s.Loc())

	rule.Head = head.Copy()
	rule.Head.SetLoc(p.s.Loc())

	defer func() {
		rule.Location.Text = p.s.Text(rule.Location.Offset, p.s.lastEnd)
	}()

	p.scan()

	switch p.s.tok {
	case tokens.LBrace:
		rule.Head.Value = BooleanTerm(true)
	case tokens.Unify:
		p.scan()
		rule.Head.Value = p.parseTermInfixCall()
		if rule.Head.Value == nil {
			return nil
		}
		rule.Head.Location.Text = p.s.Text(rule.Head.Location.Offset, p.s.lastEnd)
	default:
		p.illegal("expected else value term or rule body")
		return nil
	}

	if p.s.tok != tokens.LBrace {
		rule.Body = NewBody(NewExpr(BooleanTerm(true)))
		setLocRecursive(rule.Body, rule.Location)
		return &rule
	}

	p.scan()

	if rule.Body = p.parseBody(tokens.RBrace); rule.Body == nil {
		return nil
	}

	p.scan()

	if p.s.tok == tokens.Else {
		if rule.Else = p.parseElse(head); rule.Else == nil {
			return nil
		}
	}
	return &rule
}

func (p *Parser) parseHead(defaultRule bool) *Head {

	var head Head
	head.SetLoc(p.s.Loc())

	defer func() {
		head.Location.Text = p.s.Text(head.Location.Offset, p.s.lastEnd)
	}()

	if term := p.parseVar(); term != nil {
		head.Name = term.Value.(Var)
	} else {
		p.illegal("expected rule head name")
	}

	p.scan()

	if p.s.tok == tokens.LParen {
		p.scan()
		if p.s.tok != tokens.RParen {
			head.Args = p.parseTermList(tokens.RParen, nil)
			if head.Args == nil {
				return nil
			}
		}
		p.scan()

		if p.s.tok == tokens.LBrack {
			return nil
		}
	}

	if p.s.tok == tokens.LBrack {
		p.scan()
		head.Key = p.parseTermInfixCall()
		if head.Key == nil {
			p.illegal("expected rule key term (e.g., %s[<VALUE>] { ... })", head.Name)
		}
		if p.s.tok != tokens.RBrack {
			if _, ok := futureKeywords[head.Name.String()]; ok {
				p.hint("`import future.keywords.%[1]s` for '%[1]s' keyword", head.Name.String())
			}
			p.illegal("non-terminated rule key")
		}
		p.scan()
	}

	if p.s.tok == tokens.Unify {
		p.scan()
		head.Value = p.parseTermInfixCall()
		if head.Value == nil {
			p.illegal("expected rule value term (e.g., %s[%s] = <VALUE> { ... })", head.Name, head.Key)
		}
	} else if p.s.tok == tokens.Assign {

		if defaultRule {
			p.error(p.s.Loc(), "default rules must use = operator (not := operator)")
			return nil
		} else if head.Key != nil {
			p.error(p.s.Loc(), "partial rules must use = operator (not := operator)")
			return nil
		} else if len(head.Args) > 0 {
			p.error(p.s.Loc(), "functions must use = operator (not := operator)")
			return nil
		}

		p.scan()
		head.Assign = true
		head.Value = p.parseTermInfixCall()
		if head.Value == nil {
			p.illegal("expected rule value term (e.g., %s := <VALUE> { ... })", head.Name)
		}
	}

	if head.Value == nil && head.Key == nil {
		head.Value = BooleanTerm(true).SetLocation(head.Location)
	}

	return &head
}

func (p *Parser) parseBody(end tokens.Token) Body {
	return p.parseQuery(false, end)
}

func (p *Parser) parseQuery(requireSemi bool, end tokens.Token) Body {
	body := Body{}

	if p.s.tok == end {
		p.error(p.s.Loc(), "found empty body")
		return nil
	}

	for {

		expr := p.parseLiteral()
		if expr == nil {
			return nil
		}

		body.Append(expr)

		if p.s.tok == tokens.Semicolon {
			p.scan()
			continue
		}

		if p.s.tok == end || requireSemi {
			return body
		}

		if !p.s.skippedNL {
			// If there was already an error then don't pile this one on
			if len(p.s.errors) == 0 {
				p.illegal(`expected \n or %s or %s`, tokens.Semicolon, end)
			}
			return nil
		}
	}
}

func (p *Parser) parseLiteral() (expr *Expr) {

	offset := p.s.loc.Offset
	loc := p.s.Loc()

	defer func() {
		if expr != nil {
			loc.Text = p.s.Text(offset, p.s.lastEnd)
			expr.SetLoc(loc)
		}
	}()

	var negated bool
	switch p.s.tok {
	case tokens.Some:
		return p.parseSome()
	case tokens.Every:
		return p.parseEvery()
	case tokens.Not:
		p.scan()
		negated = true
		fallthrough
	default:
		expr := p.parseExpr()
		if expr != nil {
			expr.Negated = negated
			if p.s.tok == tokens.With {
				if expr.With = p.parseWith(); expr.With == nil {
					return nil
				}
			}
			return expr
		}
		return nil
	}
}

func (p *Parser) parseWith() []*With {

	withs := []*With{}

	for {

		with := With{
			Location: p.s.Loc(),
		}
		p.scan()

		if p.s.tok != tokens.Ident {
			p.illegal("expected ident")
			return nil
		}

		if with.Target = p.parseTerm(); with.Target == nil {
			return nil
		}

		switch with.Target.Value.(type) {
		case Ref, Var:
			break
		default:
			p.illegal("expected with target path")
		}

		if p.s.tok != tokens.As {
			p.illegal("expected as keyword")
			return nil
		}

		p.scan()

		if with.Value = p.parseTermInfixCall(); with.Value == nil {
			return nil
		}

		with.Location.Text = p.s.Text(with.Location.Offset, p.s.lastEnd)

		withs = append(withs, &with)

		if p.s.tok != tokens.With {
			break
		}
	}

	return withs
}

func (p *Parser) parseSome() *Expr {

	decl := &SomeDecl{}
	decl.SetLoc(p.s.Loc())

	// Attempt to parse "some x in xs", which will end up in
	//   SomeDecl{Symbols: ["member(x, xs)"]}
	s := p.save()
	p.scan()
	if term := p.parseTermInfixCall(); term != nil {
		if call, ok := term.Value.(Call); ok {
			switch call[0].String() {
			case Member.Name, MemberWithKey.Name: // OK
			default:
				p.illegal("expected `x in xs` or `x, y in xs` expression")
				return nil
			}

			decl.Symbols = []*Term{term}
			return NewExpr(decl).SetLocation(decl.Location)
		}
	}

	p.restore(s)
	s = p.save() // new copy for later
	var hint bool
	p.scan()
	if term := p.futureParser().parseTermInfixCall(); term != nil {
		if call, ok := term.Value.(Call); ok {
			switch call[0].String() {
			case Member.Name, MemberWithKey.Name:
				hint = true
			}
		}
	}

	// go on as before, it's `some x[...]` or illegal
	p.restore(s)
	if hint {
		p.hint("`import future.keywords.in` for `some x in xs` expressions")
	}

	for { // collecting var args

		p.scan()

		if p.s.tok != tokens.Ident {
			p.illegal("expected var")
			return nil
		}

		decl.Symbols = append(decl.Symbols, p.parseVar())

		p.scan()

		if p.s.tok != tokens.Comma {
			break
		}
	}

	return NewExpr(decl).SetLocation(decl.Location)
}

func (p *Parser) parseEvery() *Expr {
	qb := &Every{}
	qb.SetLoc(p.s.Loc())

	// TODO(sr): We'd get more accurate error messages if we didn't rely on
	// parseTermInfixCall here, but parsed "var [, var] in term" manually.
	p.scan()
	term := p.parseTermInfixCall()
	if term == nil {
		return nil
	}
	call, ok := term.Value.(Call)
	if !ok {
		p.illegal("expected `x[, y] in xs { ... }` expression")
		return nil
	}
	switch call[0].String() {
	case Member.Name: // x in xs
		qb.Value = call[1]
		qb.Domain = call[2]
	case MemberWithKey.Name: // k, v in xs
		qb.Key = call[1]
		qb.Value = call[2]
		qb.Domain = call[3]
		if _, ok := qb.Key.Value.(Var); !ok {
			p.illegal("expected key to be a variable")
			return nil
		}
	default:
		p.illegal("expected `x[, y] in xs { ... }` expression")
		return nil
	}
	if _, ok := qb.Value.Value.(Var); !ok {
		p.illegal("expected value to be a variable")
		return nil
	}
	if p.s.tok == tokens.LBrace { // every x in xs { ... }
		p.scan()
		body := p.parseBody(tokens.RBrace)
		if body == nil {
			return nil
		}
		p.scan()
		qb.Body = body
		return NewExpr(qb).SetLocation(qb.Location)
	}

	p.illegal("missing body")
	return nil
}

func (p *Parser) parseExpr() *Expr {

	lhs := p.parseTermInfixCall()
	if lhs == nil {
		return nil
	}

	if op := p.parseTermOp(tokens.Assign, tokens.Unify); op != nil {
		if rhs := p.parseTermInfixCall(); rhs != nil {
			return NewExpr([]*Term{op, lhs, rhs})
		}
		return nil
	}

	// NOTE(tsandall): the top-level call term is converted to an expr because
	// the evaluator does not support the call term type (nested calls are
	// rewritten by the compiler.)
	if call, ok := lhs.Value.(Call); ok {
		return NewExpr([]*Term(call))
	}

	return NewExpr(lhs)
}

// parseTermInfixCall consumes the next term from the input and returns it. If a
// term cannot be parsed the return value is nil and error will be recorded. The
// scanner will be advanced to the next token before returning.
// By starting out with infix relations (==, !=, <, etc) and further calling the
// other binary operators (|, &, arithmetics), it constitutes the binding
// precedence.
func (p *Parser) parseTermInfixCall() *Term {
	return p.parseTermIn(nil, true, p.s.loc.Offset)
}

func (p *Parser) parseTermInfixCallInList() *Term {
	return p.parseTermIn(nil, false, p.s.loc.Offset)
}

func (p *Parser) parseTermIn(lhs *Term, keyVal bool, offset int) *Term {
	// NOTE(sr): `in` is a bit special: besides `lhs in rhs`, it also
	// supports `key, val in rhs`, so it can have an optional second lhs.
	// `keyVal` triggers if we attempt to parse a second lhs argument (`mhs`).
	if lhs == nil {
		lhs = p.parseTermRelation(nil, offset)
	}
	if lhs != nil {
		if keyVal && p.s.tok == tokens.Comma { // second "lhs", or "middle hand side"
			s := p.save()
			p.scan()
			if mhs := p.parseTermRelation(nil, offset); mhs != nil {
				if op := p.parseTermOpName(MemberWithKey.Ref(), tokens.In); op != nil {
					if rhs := p.parseTermRelation(nil, p.s.loc.Offset); rhs != nil {
						call := p.setLoc(CallTerm(op, lhs, mhs, rhs), lhs.Location, offset, p.s.lastEnd)
						switch p.s.tok {
						case tokens.In:
							return p.parseTermIn(call, keyVal, offset)
						default:
							return call
						}
					}
				}
			}
			p.restore(s)
			return nil
		}
		if op := p.parseTermOpName(Member.Ref(), tokens.In); op != nil {
			if rhs := p.parseTermRelation(nil, p.s.loc.Offset); rhs != nil {
				call := p.setLoc(CallTerm(op, lhs, rhs), lhs.Location, offset, p.s.lastEnd)
				switch p.s.tok {
				case tokens.In:
					return p.parseTermIn(call, keyVal, offset)
				default:
					return call
				}
			}
		}
	}
	return lhs
}

func (p *Parser) parseTermRelation(lhs *Term, offset int) *Term {
	if lhs == nil {
		lhs = p.parseTermOr(nil, offset)
	}
	if lhs != nil {
		if op := p.parseTermOp(tokens.Equal, tokens.Neq, tokens.Lt, tokens.Gt, tokens.Lte, tokens.Gte); op != nil {
			if rhs := p.parseTermOr(nil, p.s.loc.Offset); rhs != nil {
				call := p.setLoc(CallTerm(op, lhs, rhs), lhs.Location, offset, p.s.lastEnd)
				switch p.s.tok {
				case tokens.Equal, tokens.Neq, tokens.Lt, tokens.Gt, tokens.Lte, tokens.Gte:
					return p.parseTermRelation(call, offset)
				default:
					return call
				}
			}
		}
	}
	return lhs
}

func (p *Parser) parseTermOr(lhs *Term, offset int) *Term {
	if lhs == nil {
		lhs = p.parseTermAnd(nil, offset)
	}
	if lhs != nil {
		if op := p.parseTermOp(tokens.Or); op != nil {
			if rhs := p.parseTermAnd(nil, p.s.loc.Offset); rhs != nil {
				call := p.setLoc(CallTerm(op, lhs, rhs), lhs.Location, offset, p.s.lastEnd)
				switch p.s.tok {
				case tokens.Or:
					return p.parseTermOr(call, offset)
				default:
					return call
				}
			}
		}
		return lhs
	}
	return nil
}

func (p *Parser) parseTermAnd(lhs *Term, offset int) *Term {
	if lhs == nil {
		lhs = p.parseTermArith(nil, offset)
	}
	if lhs != nil {
		if op := p.parseTermOp(tokens.And); op != nil {
			if rhs := p.parseTermArith(nil, p.s.loc.Offset); rhs != nil {
				call := p.setLoc(CallTerm(op, lhs, rhs), lhs.Location, offset, p.s.lastEnd)
				switch p.s.tok {
				case tokens.And:
					return p.parseTermAnd(call, offset)
				default:
					return call
				}
			}
		}
		return lhs
	}
	return nil
}

func (p *Parser) parseTermArith(lhs *Term, offset int) *Term {
	if lhs == nil {
		lhs = p.parseTermFactor(nil, offset)
	}
	if lhs != nil {
		if op := p.parseTermOp(tokens.Add, tokens.Sub); op != nil {
			if rhs := p.parseTermFactor(nil, p.s.loc.Offset); rhs != nil {
				call := p.setLoc(CallTerm(op, lhs, rhs), lhs.Location, offset, p.s.lastEnd)
				switch p.s.tok {
				case tokens.Add, tokens.Sub:
					return p.parseTermArith(call, offset)
				default:
					return call
				}
			}
		}
	}
	return lhs
}

func (p *Parser) parseTermFactor(lhs *Term, offset int) *Term {
	if lhs == nil {
		lhs = p.parseTerm()
	}
	if lhs != nil {
		if op := p.parseTermOp(tokens.Mul, tokens.Quo, tokens.Rem); op != nil {
			if rhs := p.parseTerm(); rhs != nil {
				call := p.setLoc(CallTerm(op, lhs, rhs), lhs.Location, offset, p.s.lastEnd)
				switch p.s.tok {
				case tokens.Mul, tokens.Quo, tokens.Rem:
					return p.parseTermFactor(call, offset)
				default:
					return call
				}
			}
		}
	}
	return lhs
}

func (p *Parser) parseTerm() *Term {
	if term, s := p.parsedTermCacheLookup(); s != nil {
		p.restore(s)
		return term
	}
	s0 := p.save()

	var term *Term
	switch p.s.tok {
	case tokens.Null:
		term = NullTerm().SetLocation(p.s.Loc())
	case tokens.True:
		term = BooleanTerm(true).SetLocation(p.s.Loc())
	case tokens.False:
		term = BooleanTerm(false).SetLocation(p.s.Loc())
	case tokens.Sub, tokens.Dot, tokens.Number:
		term = p.parseNumber()
	case tokens.String:
		term = p.parseString()
	case tokens.Ident:
		term = p.parseVar()
	case tokens.LBrack:
		term = p.parseArray()
	case tokens.LBrace:
		term = p.parseSetOrObject()
	case tokens.LParen:
		offset := p.s.loc.Offset
		p.scan()
		if r := p.parseTermInfixCall(); r != nil {
			if p.s.tok == tokens.RParen {
				r.Location.Text = p.s.Text(offset, p.s.tokEnd)
				term = r
			} else {
				p.error(p.s.Loc(), "non-terminated expression")
			}
		}
	default:
		p.illegalToken()
	}

	term = p.parseTermFinish(term)
	p.parsedTermCachePush(term, s0)
	return term
}

func (p *Parser) parseTermFinish(head *Term) *Term {
	if head == nil {
		return nil
	}
	offset := p.s.loc.Offset
	p.scanWS()
	switch p.s.tok {
	case tokens.LParen, tokens.Dot, tokens.LBrack:
		return p.parseRef(head, offset)
	case tokens.Whitespace:
		p.scan()
		fallthrough
	default:
		if _, ok := head.Value.(Var); ok && RootDocumentNames.Contains(head) {
			return RefTerm(head).SetLocation(head.Location)
		}
		return head
	}
}

func (p *Parser) parseNumber() *Term {
	var prefix string
	loc := p.s.Loc()
	if p.s.tok == tokens.Sub {
		prefix = "-"
		p.scan()
		switch p.s.tok {
		case tokens.Number, tokens.Dot:
			break
		default:
			p.illegal("expected number")
			return nil
		}
	}
	if p.s.tok == tokens.Dot {
		prefix += "."
		p.scan()
		if p.s.tok != tokens.Number {
			p.illegal("expected number")
			return nil
		}
	}

	// Check for multiple leading 0's, parsed by math/big.Float.Parse as decimal 0:
	// https://golang.org/pkg/math/big/#Float.Parse
	if ((len(prefix) != 0 && prefix[0] == '-') || len(prefix) == 0) &&
		len(p.s.lit) > 1 && p.s.lit[0] == '0' && p.s.lit[1] == '0' {
		p.illegal("expected number")
		return nil
	}

	// Ensure that the number is valid
	s := prefix + p.s.lit
	f, ok := new(big.Float).SetString(s)
	if !ok {
		p.illegal("invalid float")
		return nil
	}

	// Put limit on size of exponent to prevent non-linear cost of String()
	// function on big.Float from causing denial of service: https://github.com/golang/go/issues/11068
	//
	// n == sign * mantissa * 2^exp
	// 0.5 <= mantissa < 1.0
	//
	// The limit is arbitrary.
	exp := f.MantExp(nil)
	if exp > 1e5 || exp < -1e5 || f.IsInf() { // +/- inf, exp is 0
		p.error(p.s.Loc(), "number too big")
		return nil
	}

	// Note: Use the original string, do *not* round trip from
	// the big.Float as it can cause precision loss.
	r := NumberTerm(json.Number(s)).SetLocation(loc)
	return r
}

func (p *Parser) parseString() *Term {
	if p.s.lit[0] == '"' {
		var s string
		err := json.Unmarshal([]byte(p.s.lit), &s)
		if err != nil {
			p.errorf(p.s.Loc(), "illegal string literal: %s", p.s.lit)
			return nil
		}
		term := StringTerm(s).SetLocation(p.s.Loc())
		return term
	}
	return p.parseRawString()
}

func (p *Parser) parseRawString() *Term {
	if len(p.s.lit) < 2 {
		return nil
	}
	term := StringTerm(p.s.lit[1 : len(p.s.lit)-1]).SetLocation(p.s.Loc())
	return term
}

// this is the name to use for instantiating an empty set, e.g., `set()`.
var setConstructor = RefTerm(VarTerm("set"))

func (p *Parser) parseCall(operator *Term, offset int) (term *Term) {

	loc := operator.Location
	var end int

	defer func() {
		p.setLoc(term, loc, offset, end)
	}()

	p.scan() // steps over '('

	if p.s.tok == tokens.RParen { // no args, i.e. set() or any.func()
		end = p.s.tokEnd
		p.scanWS()
		if operator.Equal(setConstructor) {
			return SetTerm()
		}
		return CallTerm(operator)
	}

	if r := p.parseTermList(tokens.RParen, []*Term{operator}); r != nil {
		end = p.s.tokEnd
		p.scanWS()
		return CallTerm(r...)
	}

	return nil
}

func (p *Parser) parseRef(head *Term, offset int) (term *Term) {

	loc := head.Location
	var end int

	defer func() {
		p.setLoc(term, loc, offset, end)
	}()

	switch h := head.Value.(type) {
	case Var, *Array, Object, Set, *ArrayComprehension, *ObjectComprehension, *SetComprehension, Call:
		// ok
	default:
		p.errorf(loc, "illegal ref (head cannot be %v)", TypeName(h))
	}

	ref := []*Term{head}

	for {
		switch p.s.tok {
		case tokens.Dot:
			p.scanWS()
			if p.s.tok != tokens.Ident {
				p.illegal("expected %v", tokens.Ident)
				return nil
			}
			ref = append(ref, StringTerm(p.s.lit).SetLocation(p.s.Loc()))
			p.scanWS()
		case tokens.LParen:
			term = p.parseCall(p.setLoc(RefTerm(ref...), loc, offset, p.s.loc.Offset), offset)
			if term != nil {
				switch p.s.tok {
				case tokens.Whitespace:
					p.scan()
					end = p.s.lastEnd
					return term
				case tokens.Dot, tokens.LBrack:
					term = p.parseRef(term, offset)
				}
			}
			end = p.s.tokEnd
			return term
		case tokens.LBrack:
			p.scan()
			if term := p.parseTermInfixCall(); term != nil {
				if p.s.tok != tokens.RBrack {
					p.illegal("expected %v", tokens.LBrack)
					return nil
				}
				ref = append(ref, term)
				p.scanWS()
			} else {
				return nil
			}
		case tokens.Whitespace:
			end = p.s.lastEnd
			p.scan()
			return RefTerm(ref...)
		default:
			end = p.s.lastEnd
			return RefTerm(ref...)
		}
	}
}

func (p *Parser) parseArray() (term *Term) {

	loc := p.s.Loc()
	offset := p.s.loc.Offset

	defer func() {
		p.setLoc(term, loc, offset, p.s.tokEnd)
	}()

	p.scan()

	if p.s.tok == tokens.RBrack {
		return ArrayTerm()
	}

	potentialComprehension := true

	// Skip leading commas, eg [, x, y]
	// Supported for backwards compatibility. In the future
	// we should make this a parse error.
	if p.s.tok == tokens.Comma {
		potentialComprehension = false
		p.scan()
	}

	s := p.save()

	// NOTE(tsandall): The parser cannot attempt a relational term here because
	// of ambiguity around comprehensions. For example, given:
	//
	//  {1 | 1}
	//
	// Does this represent a set comprehension or a set containing binary OR
	// call? We resolve the ambiguity by prioritizing comprehensions.
	head := p.parseTerm()

	if head == nil {
		return nil
	}

	switch p.s.tok {
	case tokens.RBrack:
		return ArrayTerm(head)
	case tokens.Comma:
		p.scan()
		if terms := p.parseTermList(tokens.RBrack, []*Term{head}); terms != nil {
			return NewTerm(NewArray(terms...))
		}
		return nil
	case tokens.Or:
		if potentialComprehension {
			// Try to parse as if it is an array comprehension
			p.scan()
			if body := p.parseBody(tokens.RBrack); body != nil {
				return ArrayComprehensionTerm(head, body)
			}
			if p.s.tok != tokens.Comma {
				return nil
			}
		}
		// fall back to parsing as a normal array definition
	}

	p.restore(s)

	if terms := p.parseTermList(tokens.RBrack, nil); terms != nil {
		return NewTerm(NewArray(terms...))
	}
	return nil
}

func (p *Parser) parseSetOrObject() (term *Term) {
	loc := p.s.Loc()
	offset := p.s.loc.Offset

	defer func() {
		p.setLoc(term, loc, offset, p.s.tokEnd)
	}()

	p.scan()

	if p.s.tok == tokens.RBrace {
		return ObjectTerm()
	}

	potentialComprehension := true

	// Skip leading commas, eg {, x, y}
	// Supported for backwards compatibility. In the future
	// we should make this a parse error.
	if p.s.tok == tokens.Comma {
		potentialComprehension = false
		p.scan()
	}

	s := p.save()

	// Try parsing just a single term first to give comprehensions higher
	// priority to "or" calls in ambiguous situations. Eg: { a | b }
	// will be a set comprehension.
	//
	// Note: We don't know yet if it is a set or object being defined.
	head := p.parseTerm()
	if head == nil {
		return nil
	}

	switch p.s.tok {
	case tokens.Or:
		if potentialComprehension {
			return p.parseSet(s, head, potentialComprehension)
		}
	case tokens.RBrace, tokens.Comma:
		return p.parseSet(s, head, potentialComprehension)
	case tokens.Colon:
		return p.parseObject(head, potentialComprehension)
	}

	p.restore(s)

	head = p.parseTermInfixCallInList()
	if head == nil {
		return nil
	}

	switch p.s.tok {
	case tokens.RBrace, tokens.Comma:
		return p.parseSet(s, head, false)
	case tokens.Colon:
		// It still might be an object comprehension, eg { a+1: b | ... }
		return p.parseObject(head, potentialComprehension)
	}

	p.illegal("non-terminated set")
	return nil
}

func (p *Parser) parseSet(s *state, head *Term, potentialComprehension bool) *Term {
	switch p.s.tok {
	case tokens.RBrace:
		return SetTerm(head)
	case tokens.Comma:
		p.scan()
		if terms := p.parseTermList(tokens.RBrace, []*Term{head}); terms != nil {
			return SetTerm(terms...)
		}
	case tokens.Or:
		if potentialComprehension {
			// Try to parse as if it is a set comprehension
			p.scan()
			if body := p.parseBody(tokens.RBrace); body != nil {
				return SetComprehensionTerm(head, body)
			}
			if p.s.tok != tokens.Comma {
				return nil
			}
		}
		// Fall back to parsing as normal set definition
		p.restore(s)
		if terms := p.parseTermList(tokens.RBrace, nil); terms != nil {
			return SetTerm(terms...)
		}
	}
	return nil
}

func (p *Parser) parseObject(k *Term, potentialComprehension bool) *Term {
	// NOTE(tsandall): Assumption: this function is called after parsing the key
	// of the head element and then receiving a colon token from the scanner.
	// Advance beyond the colon and attempt to parse an object.
	if p.s.tok != tokens.Colon {
		panic("expected colon")
	}
	p.scan()

	s := p.save()

	// NOTE(sr): We first try to parse the value as a term (`v`), and see
	// if we can parse `{ x: v | ...}` as a comprehension.
	// However, if we encounter either a Comma or an RBace, it cannot be
	// parsed as a comprehension -- so we save double work further down
	// where `parseObjectFinish(k, v, false)` would only exercise the
	// same code paths once more.
	v := p.parseTerm()
	if v == nil {
		return nil
	}

	potentialRelation := true
	if potentialComprehension {
		switch p.s.tok {
		case tokens.RBrace, tokens.Comma:
			potentialRelation = false
			fallthrough
		case tokens.Or:
			if term := p.parseObjectFinish(k, v, true); term != nil {
				return term
			}
		}
	}

	p.restore(s)

	if potentialRelation {
		v := p.parseTermInfixCallInList()
		if v == nil {
			return nil
		}

		switch p.s.tok {
		case tokens.RBrace, tokens.Comma:
			return p.parseObjectFinish(k, v, false)
		}
	}

	p.illegal("non-terminated object")
	return nil
}

func (p *Parser) parseObjectFinish(key, val *Term, potentialComprehension bool) *Term {
	switch p.s.tok {
	case tokens.RBrace:
		return ObjectTerm([2]*Term{key, val})
	case tokens.Or:
		if potentialComprehension {
			p.scan()
			if body := p.parseBody(tokens.RBrace); body != nil {
				return ObjectComprehensionTerm(key, val, body)
			}
		} else {
			p.illegal("non-terminated object")
		}
	case tokens.Comma:
		p.scan()
		if r := p.parseTermPairList(tokens.RBrace, [][2]*Term{{key, val}}); r != nil {
			return ObjectTerm(r...)
		}
	}
	return nil
}

func (p *Parser) parseTermList(end tokens.Token, r []*Term) []*Term {
	if p.s.tok == end {
		return r
	}
	for {
		term := p.parseTermInfixCallInList()
		if term != nil {
			r = append(r, term)
			switch p.s.tok {
			case end:
				return r
			case tokens.Comma:
				p.scan()
				if p.s.tok == end {
					return r
				}
				continue
			default:
				p.illegal(fmt.Sprintf("expected %q or %q", tokens.Comma, end))
				return nil
			}
		}
		return nil
	}
}

func (p *Parser) parseTermPairList(end tokens.Token, r [][2]*Term) [][2]*Term {
	if p.s.tok == end {
		return r
	}
	for {
		key := p.parseTermInfixCallInList()
		if key != nil {
			switch p.s.tok {
			case tokens.Colon:
				p.scan()
				if val := p.parseTermInfixCallInList(); val != nil {
					r = append(r, [2]*Term{key, val})
					switch p.s.tok {
					case end:
						return r
					case tokens.Comma:
						p.scan()
						if p.s.tok == end {
							return r
						}
						continue
					default:
						p.illegal(fmt.Sprintf("expected %q or %q", tokens.Comma, end))
						return nil
					}
				}
			default:
				p.illegal(fmt.Sprintf("expected %q", tokens.Colon))
				return nil
			}
		}
		return nil
	}
}

func (p *Parser) parseTermOp(values ...tokens.Token) *Term {
	for i := range values {
		if p.s.tok == values[i] {
			r := RefTerm(VarTerm(fmt.Sprint(p.s.tok)).SetLocation(p.s.Loc())).SetLocation(p.s.Loc())
			p.scan()
			return r
		}
	}
	return nil
}

func (p *Parser) parseTermOpName(ref Ref, values ...tokens.Token) *Term {
	for i := range values {
		if p.s.tok == values[i] {
			for _, r := range ref {
				r.SetLocation(p.s.Loc())
			}
			t := RefTerm(ref...)
			t.SetLocation(p.s.Loc())
			p.scan()
			return t
		}
	}
	return nil
}

func (p *Parser) parseVar() *Term {

	s := p.s.lit

	term := VarTerm(s).SetLocation(p.s.Loc())

	// Update wildcard values with unique identifiers
	if term.Equal(Wildcard) {
		term.Value = Var(p.genwildcard())
	}

	return term
}

func (p *Parser) genwildcard() string {
	c := p.s.wildcard
	p.s.wildcard++
	return fmt.Sprintf("%v%d", WildcardPrefix, c)
}

func (p *Parser) error(loc *location.Location, reason string) {
	p.errorf(loc, reason)
}

func (p *Parser) errorf(loc *location.Location, f string, a ...interface{}) {
	msg := strings.Builder{}
	fmt.Fprintf(&msg, f, a...)

	switch len(p.s.hints) {
	case 0: // nothing to do
	case 1:
		msg.WriteString(" (hint: ")
		msg.WriteString(p.s.hints[0])
		msg.WriteRune(')')
	default:
		msg.WriteString(" (hints: ")
		for i, h := range p.s.hints {
			if i > 0 {
				msg.WriteString(", ")
			}
			msg.WriteString(h)
		}
		msg.WriteRune(')')
	}

	p.s.errors = append(p.s.errors, &Error{
		Code:     ParseErr,
		Message:  msg.String(),
		Location: loc,
		Details:  newParserErrorDetail(p.s.s.Bytes(), loc.Offset),
	})
	p.s.hints = nil
}

func (p *Parser) hint(f string, a ...interface{}) {
	p.s.hints = append(p.s.hints, fmt.Sprintf(f, a...))
}

func (p *Parser) illegal(note string, a ...interface{}) {
	tok := p.s.tok.String()

	if p.s.tok == tokens.Illegal {
		p.errorf(p.s.Loc(), "illegal token")
		return
	}

	tokType := "token"
	if p.s.tok >= tokens.Package && p.s.tok <= tokens.False {
		tokType = "keyword"
	}

	note = fmt.Sprintf(note, a...)
	if len(note) > 0 {
		p.errorf(p.s.Loc(), "unexpected %s %s: %s", tok, tokType, note)
	} else {
		p.errorf(p.s.Loc(), "unexpected %s %s", tok, tokType)
	}
}

func (p *Parser) illegalToken() {
	p.illegal("")
}

func (p *Parser) scan() {
	p.doScan(true)
}

func (p *Parser) scanWS() {
	p.doScan(false)
}

func (p *Parser) doScan(skipws bool) {

	// NOTE(tsandall): the last position is used to compute the "text" field for
	// complex AST nodes. Whitespace never affects the last position of an AST
	// node so do not update it when scanning.
	if p.s.tok != tokens.Whitespace {
		p.s.lastEnd = p.s.tokEnd
		p.s.skippedNL = false
	}

	var errs []scanner.Error
	for {
		var pos scanner.Position
		p.s.tok, pos, p.s.lit, errs = p.s.s.Scan()

		p.s.tokEnd = pos.End
		p.s.loc.Row = pos.Row
		p.s.loc.Col = pos.Col
		p.s.loc.Offset = pos.Offset
		p.s.loc.Text = p.s.Text(pos.Offset, pos.End)

		for _, err := range errs {
			p.error(p.s.Loc(), err.Message)
		}

		if len(errs) > 0 {
			p.s.tok = tokens.Illegal
		}

		if p.s.tok == tokens.Whitespace {
			if p.s.lit == "\n" {
				p.s.skippedNL = true
			}
			if skipws {
				continue
			}
		}

		if p.s.tok != tokens.Comment {
			break
		}

		// For backwards compatibility leave a nil
		// Text value if there is no text rather than
		// an empty string.
		var commentText []byte
		if len(p.s.lit) > 1 {
			commentText = []byte(p.s.lit[1:])
		}
		comment := NewComment(commentText)
		comment.SetLoc(p.s.Loc())
		p.s.comments = append(p.s.comments, comment)
	}
}

func (p *Parser) save() *state {
	cpy := *p.s
	s := *cpy.s
	cpy.s = &s
	return &cpy
}

func (p *Parser) restore(s *state) {
	p.s = s
}

func setLocRecursive(x interface{}, loc *location.Location) {
	NewGenericVisitor(func(x interface{}) bool {
		if node, ok := x.(Node); ok {
			node.SetLoc(loc)
		}
		return false
	}).Walk(x)
}

func (p *Parser) setLoc(term *Term, loc *location.Location, offset, end int) *Term {
	if term != nil {
		cpy := *loc
		term.Location = &cpy
		term.Location.Text = p.s.Text(offset, end)
	}
	return term
}

func (p *Parser) validateDefaultRuleValue(rule *Rule) bool {
	if rule.Head.Value == nil {
		p.error(rule.Loc(), "illegal default rule (must have a value)")
		return false
	}

	valid := true
	vis := NewGenericVisitor(func(x interface{}) bool {
		switch x.(type) {
		case *ArrayComprehension, *ObjectComprehension, *SetComprehension: // skip closures
			return true
		case Ref, Var, Call:
			p.error(rule.Loc(), fmt.Sprintf("illegal default rule (value cannot contain %v)", TypeName(x)))
			valid = false
			return true
		}
		return false
	})

	vis.Walk(rule.Head.Value.Value)
	return valid
}

type rawAnnotation struct {
	Scope   string                `json:"scope"`
	Schemas []rawSchemaAnnotation `json:"schemas"`
}

type rawSchemaAnnotation map[string]interface{}

type metadataParser struct {
	buf      *bytes.Buffer
	comments []*Comment
	loc      *location.Location
}

func newMetadataParser(loc *Location) *metadataParser {
	return &metadataParser{loc: loc, buf: bytes.NewBuffer(nil)}
}

func (b *metadataParser) Append(c *Comment) {
	b.buf.Write(bytes.TrimPrefix(c.Text, []byte(" ")))
	b.buf.WriteByte('\n')
	b.comments = append(b.comments, c)
}

var yamlLineErrRegex = regexp.MustCompile(`^yaml: line ([[:digit:]]+):`)

func (b *metadataParser) Parse() (*Annotations, error) {

	var raw rawAnnotation

	if len(bytes.TrimSpace(b.buf.Bytes())) == 0 {
		return nil, fmt.Errorf("expected METADATA block, found whitespace")
	}

	if err := yaml.Unmarshal(b.buf.Bytes(), &raw); err != nil {
		match := yamlLineErrRegex.FindStringSubmatch(err.Error())
		if len(match) == 2 {
			n, err2 := strconv.Atoi(match[1])
			if err2 == nil {
				index := n - 1 // line numbering is 1-based so subtract one from row
				if index >= len(b.comments) {
					b.loc = b.comments[len(b.comments)-1].Location
				} else {
					b.loc = b.comments[index].Location
				}
			}
		}
		return nil, err
	}

	var result Annotations
	result.Scope = raw.Scope

	for _, pair := range raw.Schemas {
		var k string
		var v interface{}
		for k, v = range pair {
		}

		var a SchemaAnnotation
		var err error

		a.Path, err = ParseRef(k)
		if err != nil {
			return nil, fmt.Errorf("invalid document reference")
		}

		switch v := v.(type) {
		case string:
			a.Schema, err = parseSchemaRef(v)
			if err != nil {
				return nil, err
			}
		case map[interface{}]interface{}:
			w, err := convertYAMLMapKeyTypes(v, nil)
			if err != nil {
				return nil, errors.Wrap(err, "invalid schema definition")
			}
			a.Definition = &w
		default:
			return nil, fmt.Errorf("invalid schema declaration for path %q", k)
		}

		result.Schemas = append(result.Schemas, &a)
	}

	result.Location = b.loc
	return &result, nil
}

var errInvalidSchemaRef = fmt.Errorf("invalid schema reference")

// NOTE(tsandall): 'schema' is not registered as a root because it's not
// supported by the compiler or evaluator today. Once we fix that, we can remove
// this function.
func parseSchemaRef(s string) (Ref, error) {

	term, err := ParseTerm(s)
	if err == nil {
		switch v := term.Value.(type) {
		case Var:
			if term.Equal(SchemaRootDocument) {
				return SchemaRootRef.Copy(), nil
			}
		case Ref:
			if v.HasPrefix(SchemaRootRef) {
				return v, nil
			}
		}
	}

	return nil, errInvalidSchemaRef
}

func convertYAMLMapKeyTypes(x interface{}, path []string) (interface{}, error) {
	var err error
	switch x := x.(type) {
	case map[interface{}]interface{}:
		result := make(map[string]interface{}, len(x))
		for k, v := range x {
			str, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("invalid map key type(s): %v", strings.Join(path, "/"))
			}
			result[str], err = convertYAMLMapKeyTypes(v, append(path, str))
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	case []interface{}:
		for i := range x {
			x[i], err = convertYAMLMapKeyTypes(x[i], append(path, fmt.Sprintf("%d", i)))
			if err != nil {
				return nil, err
			}
		}
		return x, nil
	default:
		return x, nil
	}
}

// futureKeywords is the source of truth for future keywords that will
// eventually become standard keywords inside of Rego.
var futureKeywords = map[string]tokens.Token{
	"in":    tokens.In,
	"every": tokens.Every,
}

func (p *Parser) futureImport(imp *Import, allowedFutureKeywords map[string]tokens.Token) {
	path := imp.Path.Value.(Ref)

	if len(path) == 1 || !path[1].Equal(StringTerm("keywords")) {
		p.errorf(imp.Path.Location, "invalid import, must be `future.keywords`")
		return
	}

	if imp.Alias != "" {
		p.errorf(imp.Path.Location, "future keyword imports cannot be aliased")
		return
	}

	kwds := make([]string, 0, len(allowedFutureKeywords))
	for k := range allowedFutureKeywords {
		kwds = append(kwds, k)
	}

	switch len(path) {
	case 2: // all keywords imported, nothing to do
		// TODO(sr): remove when ready
		for i, kw := range kwds {
			if kw == "every" {
				kwds = append(kwds[:i], kwds[i+1:]...)
			}
		}
	case 3: // one keyword imported
		kw, ok := path[2].Value.(String)
		if !ok {
			p.errorf(imp.Path.Location, "invalid import, must be `future.keywords.x`, e.g. `import future.keywords.in`")
			return
		}
		keyword := string(kw)
		_, ok = allowedFutureKeywords[keyword]
		if !ok {
			sort.Strings(kwds) // so the error message is stable
			p.errorf(imp.Path.Location, "unexpected keyword, must be one of %v", kwds)
			return
		}

		kwds = []string{keyword} // overwrite
	}
	for _, kw := range kwds {
		p.s.s.AddKeyword(kw, allowedFutureKeywords[kw])
	}
}
