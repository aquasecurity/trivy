package expressions

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

type TokenType uint16

const (
	TokenName TokenType = iota
	TokenOpenParen
	TokenCloseParen
	TokenComma
	TokenDot
	TokenLiteralString
	TokenLiteralInteger
	TokenLiteralFloat
	TokenNewLine
)

type Token struct {
	Type TokenType
	Data interface{}
}

type lexer struct {
	reader *bufio.Reader
}

func lex(expression string) ([]Token, error) {
	lexer := &lexer{
		reader: bufio.NewReader(strings.NewReader(expression)),
	}
	return lexer.Lex()
}

func (l *lexer) unread() {
	_ = l.reader.UnreadRune()
}

func (l *lexer) read() (rune, error) {
	r, _, err := l.reader.ReadRune()
	return r, err
}

func (l *lexer) Lex() ([]Token, error) {
	var tokens []Token

	for {
		r, err := l.read()
		if err != nil {
			break
		}

		switch r {
		case ' ', '\t', '\r':
			continue
		case '\n':
			tokens = append(tokens, Token{Type: TokenNewLine})
		case '(':
			tokens = append(tokens, Token{Type: TokenOpenParen})
		case ')':
			tokens = append(tokens, Token{Type: TokenCloseParen})
		case ',':
			tokens = append(tokens, Token{Type: TokenComma})
		case '.':
			tokens = append(tokens, Token{Type: TokenDot})
		case '"', '\'':
			token, err := l.lexString(r)
			if err != nil {
				return nil, fmt.Errorf("string parse error: %w", err)
			}
			tokens = append(tokens, token)
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			l.unread()
			token, err := l.lexNumber()
			if err != nil {
				return nil, fmt.Errorf("number parse error: %w", err)
			}
			tokens = append(tokens, token)
		default:
			l.unread()
			tokens = append(tokens, l.lexKeyword())
		}
	}

	return tokens, nil
}

func (l *lexer) lexString(terminator rune) (Token, error) {
	var sb strings.Builder
	for {
		r, err := l.read()
		if err != nil {
			break
		}
		if r == '\\' {
			r, err := l.readEscapedChar()
			if err != nil {
				return Token{}, fmt.Errorf("bad escape: %w", err)
			}
			sb.WriteRune(r)
			continue
		}
		if r == terminator {
			break
		}
		sb.WriteRune(r)
	}
	return Token{
		Type: TokenLiteralString,
		Data: sb.String(),
	}, nil
}

func (l *lexer) readEscapedChar() (rune, error) {
	r, err := l.read()
	if err != nil {
		return 0, fmt.Errorf("unexpected EOF")
	}
	switch r {
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case '"', '\'':
		return r, nil
	default:
		return 0, fmt.Errorf("'%c' is not a supported escape sequence", r)
	}
}

func (l *lexer) lexNumber() (Token, error) {

	var sb strings.Builder
	var decimal bool

LOOP:
	for {
		r, err := l.read()
		if err != nil {
			break
		}
		switch r {
		case '.':
			decimal = true
			sb.WriteRune('.')
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			sb.WriteRune(r)
		default:
			l.unread()
			break LOOP
		}
	}

	raw := sb.String()
	if decimal {
		fl, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return Token{}, err
		}
		return Token{
			Type: TokenLiteralFloat,
			Data: fl,
		}, nil
	}

	i, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return Token{}, err
	}
	return Token{
		Type: TokenLiteralInteger,
		Data: i,
	}, nil
}

func (l *lexer) lexKeyword() Token {
	var sb strings.Builder
LOOP:
	for {
		r, err := l.read()
		if err != nil {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			sb.WriteRune(r)
		default:
			l.unread()
			break LOOP
		}
	}
	return Token{
		Type: TokenName,
		Data: sb.String(),
	}
}
