package lexer

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/licensing/expression/token"

	"github.com/stretchr/testify/assert"
)

func TestNextToken(t *testing.T) {
	tests := []struct {
		name              string
		licenseExpression string
		expectTokens      []token.Token
	}{
		{
			name:              "empty input",
			licenseExpression: "",
			expectTokens: []token.Token{
				{
					Type:    token.EOF,
					Literal: string(byte(0)),
				},
			},
		},
		{
			name:              "single ident",
			licenseExpression: "GPL1.0+",
			expectTokens: []token.Token{
				{
					Type:    token.IDENT,
					Literal: "GPL1.0+",
				},
			},
		},
		{
			name:              "multi ident",
			licenseExpression: "Public Domain",
			expectTokens: []token.Token{
				{
					Type:    token.IDENT,
					Literal: "Public",
				},
				{
					Type:    token.IDENT,
					Literal: "Domain",
				},
			},
		},
		{
			name:              "AND OR operator",
			licenseExpression: "Public Domain AND GPL1.0+ OR GPL2.0_or_later",
			expectTokens: []token.Token{
				{
					Type:    token.IDENT,
					Literal: "Public",
				},
				{
					Type:    token.IDENT,
					Literal: "Domain",
				},
				{
					Type:    token.AND,
					Literal: "AND",
				},
				{
					Type:    token.IDENT,
					Literal: "GPL1.0+",
				},
				{
					Type:    token.OR,
					Literal: "OR",
				},
				{
					Type:    token.IDENT,
					Literal: "GPL2.0_or_later",
				},
			},
		},
		{
			name:              "PAREN operator",
			licenseExpression: "(GPL1.0+ OR GPL2.0)",
			expectTokens: []token.Token{
				{
					Type:    token.LPAREN,
					Literal: "(",
				},
				{
					Type:    token.IDENT,
					Literal: "GPL1.0+",
				},
				{
					Type:    token.OR,
					Literal: "OR",
				},
				{
					Type:    token.IDENT,
					Literal: "GPL2.0",
				},
				{
					Type:    token.RPAREN,
					Literal: ")",
				},
			},
		},
		{
			name:              "illegal string",
			licenseExpression: "GPL1.0+" + string(byte(0x20)) + "あ" + "🇯🇵" + "AND LGPL1.0",
			expectTokens: []token.Token{
				{
					Type:    token.IDENT,
					Literal: "GPL1.0+",
				},
				{
					Type:    token.AND,
					Literal: "AND",
				},
				{
					Type:    token.IDENT,
					Literal: "LGPL1.0+",
				},
			},
		},
	}

	for _, tt := range tests {
		l := New(tt.licenseExpression)
		for _, expect := range tt.expectTokens {
			tok := l.NextToken()

			// Skip literal
			if tok.Type == token.ILLEGAL {
				continue
			}

			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, expect.Type, tok.Type)
				assert.Equal(t, expect.Literal, tok.Literal)
			})
		}
	}
}
