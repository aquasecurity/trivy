// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package scanner

import (
	"fmt"
	"io"
	"io/ioutil"
	"unicode"
	"unicode/utf8"

	"github.com/open-policy-agent/opa/ast/internal/tokens"
)

const bom = 0xFEFF

// Scanner is used to tokenize an input stream of
// Rego source code.
type Scanner struct {
	offset   int
	row      int
	col      int
	bs       []byte
	curr     rune
	width    int
	errors   []Error
	keywords map[string]tokens.Token
}

// Error represents a scanner error.
type Error struct {
	Pos     Position
	Message string
}

// Position represents a point in the scanned source code.
type Position struct {
	Offset int // start offset in bytes
	End    int // end offset in bytes
	Row    int // line number computed in bytes
	Col    int // column number computed in bytes
}

// New returns an initialized scanner that will scan
// through the source code provided by the io.Reader.
func New(r io.Reader) (*Scanner, error) {

	bs, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	s := &Scanner{
		offset:   0,
		row:      1,
		col:      0,
		bs:       bs,
		curr:     -1,
		width:    0,
		keywords: tokens.Keywords(),
	}

	s.next()

	if s.curr == bom {
		s.next()
	}

	return s, nil
}

// Bytes returns the raw bytes for the full source
// which the scanner has read in.
func (s *Scanner) Bytes() []byte {
	return s.bs
}

// String returns a human readable string of the current scanner state.
func (s *Scanner) String() string {
	return fmt.Sprintf("<curr: %q, offset: %d, len: %d>", s.curr, s.offset, len(s.bs))
}

// Keyword will return a token for the passed in
// literal value. If the value is a Rego keyword
// then the appropriate token is returned. Everything
// else is an Ident.
func (s *Scanner) Keyword(lit string) tokens.Token {
	if tok, ok := s.keywords[lit]; ok {
		return tok
	}
	return tokens.Ident
}

// AddKeyword adds a string -> token mapping to this Scanner instance.
func (s *Scanner) AddKeyword(kw string, tok tokens.Token) {
	s.keywords[kw] = tok
}

// WithKeywords returns a new copy of the Scanner struct `s`, with the set
// of known keywords being that of `s` with `kws` added.
func (s *Scanner) WithKeywords(kws map[string]tokens.Token) *Scanner {
	cpy := *s
	cpy.keywords = make(map[string]tokens.Token, len(s.keywords)+len(kws))
	for kw, tok := range s.keywords {
		cpy.AddKeyword(kw, tok)
	}
	for k, t := range kws {
		cpy.AddKeyword(k, t)
	}
	return &cpy
}

// WithoutKeywords returns a new copy of the Scanner struct `s`, with the
// set of known keywords being that of `s` with `kws` removed.
// The previously known keywords are returned for a convenient reset.
func (s *Scanner) WithoutKeywords(kws map[string]tokens.Token) (*Scanner, map[string]tokens.Token) {
	cpy := *s
	kw := s.keywords
	cpy.keywords = make(map[string]tokens.Token, len(s.keywords)-len(kws))
	for kw, tok := range s.keywords {
		if _, ok := kws[kw]; !ok {
			cpy.AddKeyword(kw, tok)
		}
	}
	return &cpy, kw
}

// Scan will increment the scanners position in the source
// code until the next token is found. The token, starting position
// of the token, string literal, and any errors encountered are
// returned. A token will always be returned, the caller must check
// for any errors before using the other values.
func (s *Scanner) Scan() (tokens.Token, Position, string, []Error) {

	pos := Position{Offset: s.offset - s.width, Row: s.row, Col: s.col}
	var tok tokens.Token
	var lit string

	if s.isWhitespace() {
		lit = string(s.curr)
		s.next()
		tok = tokens.Whitespace
	} else if isLetter(s.curr) {
		lit = s.scanIdentifier()
		tok = s.Keyword(lit)
	} else if isDecimal(s.curr) {
		lit = s.scanNumber()
		tok = tokens.Number
	} else {
		ch := s.curr
		s.next()
		switch ch {
		case -1:
			tok = tokens.EOF
		case '#':
			lit = s.scanComment()
			tok = tokens.Comment
		case '"':
			lit = s.scanString()
			tok = tokens.String
		case '`':
			lit = s.scanRawString()
			tok = tokens.String
		case '[':
			tok = tokens.LBrack
		case ']':
			tok = tokens.RBrack
		case '{':
			tok = tokens.LBrace
		case '}':
			tok = tokens.RBrace
		case '(':
			tok = tokens.LParen
		case ')':
			tok = tokens.RParen
		case ',':
			tok = tokens.Comma
		case ':':
			if s.curr == '=' {
				s.next()
				tok = tokens.Assign
			} else {
				tok = tokens.Colon
			}
		case '+':
			tok = tokens.Add
		case '-':
			tok = tokens.Sub
		case '*':
			tok = tokens.Mul
		case '/':
			tok = tokens.Quo
		case '%':
			tok = tokens.Rem
		case '&':
			tok = tokens.And
		case '|':
			tok = tokens.Or
		case '=':
			if s.curr == '=' {
				s.next()
				tok = tokens.Equal
			} else {
				tok = tokens.Unify
			}
		case '>':
			if s.curr == '=' {
				s.next()
				tok = tokens.Gte
			} else {
				tok = tokens.Gt
			}
		case '<':
			if s.curr == '=' {
				s.next()
				tok = tokens.Lte
			} else {
				tok = tokens.Lt
			}
		case '!':
			if s.curr == '=' {
				s.next()
				tok = tokens.Neq
			} else {
				s.error("illegal ! character")
			}
		case ';':
			tok = tokens.Semicolon
		case '.':
			tok = tokens.Dot
		}
	}

	pos.End = s.offset - s.width
	errs := s.errors
	s.errors = nil

	return tok, pos, lit, errs
}

func (s *Scanner) scanIdentifier() string {
	start := s.offset - 1
	for isLetter(s.curr) || isDigit(s.curr) {
		s.next()
	}
	return string(s.bs[start : s.offset-1])
}

func (s *Scanner) scanNumber() string {

	start := s.offset - 1

	if s.curr != '.' {
		for isDecimal(s.curr) {
			s.next()
		}
	}

	if s.curr == '.' {
		s.next()
		var found bool
		for isDecimal(s.curr) {
			s.next()
			found = true
		}
		if !found {
			s.error("expected fraction")
		}
	}

	if lower(s.curr) == 'e' {
		s.next()
		if s.curr == '+' || s.curr == '-' {
			s.next()
		}
		var found bool
		for isDecimal(s.curr) {
			s.next()
			found = true
		}
		if !found {
			s.error("expected exponent")
		}
	}

	// Scan any digits following the decimals to get the
	// entire invalid number/identifier.
	// Example: 0a2b should be a single invalid number "0a2b"
	// rather than a number "0", followed by identifier "a2b".
	if isLetter(s.curr) {
		s.error("illegal number format")
		for isLetter(s.curr) || isDigit(s.curr) {
			s.next()
		}
	}

	return string(s.bs[start : s.offset-1])
}

func (s *Scanner) scanString() string {
	start := s.literalStart()
	for {
		ch := s.curr

		if ch == '\n' || ch < 0 {
			s.error("non-terminated string")
			break
		}

		s.next()

		if ch == '"' {
			break
		}

		if ch == '\\' {
			switch s.curr {
			case '\\', '"', '/', 'b', 'f', 'n', 'r', 't':
				s.next()
			case 'u':
				s.next()
				s.next()
				s.next()
				s.next()
			default:
				s.error("illegal escape sequence")
			}
		}
	}

	return string(s.bs[start : s.offset-1])
}

func (s *Scanner) scanRawString() string {
	start := s.literalStart()
	for {
		ch := s.curr
		s.next()
		if ch == '`' {
			break
		} else if ch < 0 {
			s.error("non-terminated string")
			break
		}
	}
	return string(s.bs[start : s.offset-1])
}

func (s *Scanner) scanComment() string {
	start := s.literalStart()
	for s.curr != '\n' && s.curr != -1 {
		s.next()
	}
	end := s.offset - 1
	// Trim carriage returns that precede the newline
	if s.offset > 1 && s.bs[s.offset-2] == '\r' {
		end = end - 1
	}
	return string(s.bs[start:end])
}

func (s *Scanner) next() {

	if s.offset >= len(s.bs) {
		s.curr = -1
		s.offset = len(s.bs) + 1
		return
	}

	s.curr = rune(s.bs[s.offset])
	s.width = 1

	if s.curr == 0 {
		s.error("illegal null character")
	} else if s.curr >= utf8.RuneSelf {
		s.curr, s.width = utf8.DecodeRune(s.bs[s.offset:])
		if s.curr == utf8.RuneError && s.width == 1 {
			s.error("illegal utf-8 character")
		} else if s.curr == bom && s.offset > 0 {
			s.error("illegal byte-order mark")
		}
	}

	s.offset += s.width

	if s.curr == '\n' {
		s.row++
		s.col = 0
	} else {
		s.col++
	}
}

func (s *Scanner) literalStart() int {
	// The current offset is at the first character past the literal delimiter (#, ", `, etc.)
	// Need to subtract width of first character (plus one for the delimiter).
	return s.offset - (s.width + 1)
}

// From the Go scanner (src/go/scanner/scanner.go)

func isLetter(ch rune) bool {
	return 'a' <= lower(ch) && lower(ch) <= 'z' || ch == '_'
}

func isDigit(ch rune) bool {
	return isDecimal(ch) || ch >= utf8.RuneSelf && unicode.IsDigit(ch)
}

func isDecimal(ch rune) bool { return '0' <= ch && ch <= '9' }

func lower(ch rune) rune { return ('a' - 'A') | ch } // returns lower-case ch iff ch is ASCII letter

func (s *Scanner) isWhitespace() bool {
	return s.curr == ' ' || s.curr == '\t' || s.curr == '\n' || s.curr == '\r'
}

func (s *Scanner) error(reason string) {
	s.errors = append(s.errors, Error{Pos: Position{
		Offset: s.offset,
		Row:    s.row,
		Col:    s.col,
	}, Message: reason})
}
