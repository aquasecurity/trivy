package parser

import (
	"fmt"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/licensing/expression/lexer"
	"github.com/aquasecurity/trivy/pkg/licensing/expression/token"
)

var (
	ErrInvalidExpression = xerrors.New("invalid expression error")
)

type Parser struct {
	lex         *lexer.Lexer
	normalizeFn []NormalizeFunc
}

type LicenseExpression struct {
	Node     Node
	Operator string
	Next     *LicenseExpression
}

type Node struct {
	License           string
	LicenseExpression *LicenseExpression
}

type NormalizeFunc func(n string) string

func New(lex *lexer.Lexer) *Parser {
	return &Parser{
		lex: lex,
	}
}

func (p *Parser) RegisterNormalizeFunc(fn ...NormalizeFunc) *Parser {
	p.normalizeFn = append(p.normalizeFn, fn...)
	return p
}

func (p *Parser) Parse() (*LicenseExpression, error) {
	root := &LicenseExpression{}
	cursor := root
	stack := Stack{}

	for tok := p.lex.NextToken(); tok.Type != token.EOF; tok = p.lex.NextToken() {
		switch tok.Type {
		case token.IDENT:
			if cursor.Node.License == "" {
				cursor.Node = Node{License: tok.Literal}
			} else {
				cursor.Node.License = fmt.Sprintf("%s %s", cursor.Node.License, tok.Literal)
			}
		case token.AND, token.OR:
			cursor.Operator = string(tok.Type)
			cursor.Next = &LicenseExpression{}
			cursor = cursor.Next
		case token.LPAREN, token.LBRACE:
			p := Pair{root: root, cursor: cursor, bracket: tok.Type}
			stack.Push(p)
			root = &LicenseExpression{}
			cursor = root
		case token.RPAREN, token.RBRACE:
			e := stack.Pop()
			if e.bracket == token.LPAREN {
				if tok.Type != token.RPAREN {
					return nil, ErrInvalidExpression
				}
			} else if e.bracket == token.LBRACE {
				if tok.Type != token.RBRACE {
					return nil, ErrInvalidExpression
				}
			}
			e.cursor.Node.LicenseExpression = root
			cursor = e.cursor
			root = e.root
		}
	}
	if !stack.IsEmpty() {
		return nil, ErrInvalidExpression
	}
	return root, nil
}
func (p *Parser) Normalize(l *LicenseExpression) string {
	cursor := l

	var str string
	for ; cursor != nil; cursor = cursor.Next {
		str = strings.Join([]string{str, p.normalize(cursor.Node), cursor.Operator}, " ")
	}
	return strings.TrimSpace(str)
}

func (p *Parser) normalize(n Node) string {
	if n.LicenseExpression != nil {
		return fmt.Sprintf("( %s )", p.Normalize(n.LicenseExpression))
	}
	for _, fn := range p.normalizeFn {
		n.License = fn(n.License)
	}
	return n.License
}
