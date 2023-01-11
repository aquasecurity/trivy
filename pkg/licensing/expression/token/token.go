package token

import "strings"

const (
	ILLEGAL = "ILLEGAL"
	EOF     = "EOF"

	IDENT = "IDENT"

	LPAREN = "("
	RPAREN = ")"

	AND = "AND"
	OR  = "OR"
)

var keywords = map[string]TokenType{
	"AND": AND,
	"OR":  OR,
}

type TokenType string

type Token struct {
	Type    TokenType
	Literal string
}

func LookupIdent(ident string) TokenType {
	if tok, ok := keywords[strings.ToUpper(ident)]; ok {
		return tok
	}
	return IDENT
}
