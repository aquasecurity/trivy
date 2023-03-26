package expression

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	multierror "github.com/hashicorp/go-multierror"
)

type Lexer struct {
	s      *bufio.Scanner
	result Expression
	errs   error
}

func NewLexer(reader io.Reader) *Lexer {
	scanner := bufio.NewScanner(reader)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		// The implementation references bufio.ScanWords()

		// Skip leading spaces.
		start := 0
		for width := 0; start < len(data); start += width {
			var r rune
			r, width = utf8.DecodeRune(data[start:])
			if !unicode.IsSpace(r) {
				break
			}
		}
		// Process terminal symbols
		if len(data) > start && (data[start] == '(' || data[start] == ')' || data[start] == '+') {
			return start + 1, data[start : start+1], nil
		}

		// Scan until space or token, marking end of word.
		for width, i := 0, start; i < len(data); i += width {
			var r rune
			r, width = utf8.DecodeRune(data[i:])
			switch r {
			case '(', ')':
				return i, data[start:i], nil
			case '+':
				// Peek the next rune
				if len(data) > i+width {
					adv := i
					i += width
					r, width = utf8.DecodeRune(data[i:])
					if unicode.IsSpace(r) || r == '(' || r == ')' {
						return adv, data[start:adv], nil
					}
				} else if atEOF {
					return i, data[start:i], nil
				}
			default:
				if unicode.IsSpace(r) {
					return i + width, data[start:i], nil
				}
			}
		}
		// If we're at EOF, we have a final, non-empty, non-terminated word. Return it.
		if atEOF && len(data) > start {
			return len(data), data[start:], nil
		}
		// Request more data.
		return start, nil, nil
	})

	return &Lexer{
		s: scanner,
	}
}

func (l *Lexer) Lex(lval *yySymType) int {
	if !l.s.Scan() {
		return 0
	}

	var token int
	literal := l.s.Text()
	switch literal {
	case "(", ")", "+":
		token = int(literal[0])
	default:
		token = lookup(literal)
	}

	lval.token = Token{
		token:   token,
		literal: literal,
	}

	if err := l.s.Err(); err != nil {
		l.errs = multierror.Append(l.errs, l.s.Err())
	}

	return lval.token.token
}

func (l *Lexer) Error(e string) {
	l.errs = multierror.Append(l.errs, errors.New(e))
}

func (l *Lexer) Err() error {
	return l.errs
}

func lookup(t string) int {
	t = strings.ToUpper(t)
	for i, name := range yyToknames {
		if t == name {
			return yyPrivate + (i - 1)
		}
	}
	return IDENT
}
