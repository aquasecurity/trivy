// Package gintersect provides methods to check whether the intersection of several globs matches a non-empty set of strings.
package gintersect

import (
	"fmt"
	"strings"
)

// Glob represents a glob.
type Glob []Token

// NewGlob constructs a Glob from the given string by tokenizing and then simplifying it, or reports errors if any.
func NewGlob(input string) (Glob, error) {
	tokens, err := Tokenize([]rune(input))
	if err != nil {
		return nil, err
	}

	tokens = Simplify(tokens)

	return Glob(tokens), nil
}

// TokenType is the type of a Token.
type TokenType uint

const (
	TTCharacter TokenType = iota
	TTDot
	TTSet
)

// Flag applies to a token.
type Flag uint

func (f Flag) String() (s string) {
	for r, flag := range flagRunes {
		if f == flag {
			s = string(r)
			break
		}
	}
	return
}

const (
	FlagNone = iota
	FlagPlus
	FlagStar
)

// Token is the element that makes up a Glob.
type Token interface {
	Type() TokenType
	Flag() Flag
	SetFlag(Flag)
	// Equal describes whether the given Token is exactly equal to this one, barring differences in flags.
	Equal(Token) bool
	String() string
}

// token is the base for all structs implementing Token.
type token struct {
	ttype TokenType
	flag  Flag
}

func (t token) Type() TokenType {
	return t.ttype
}

func (t token) Flag() Flag {
	return t.flag
}

func (t *token) SetFlag(f Flag) {
	t.flag = f
}

// character is a specific rune. It implements Token.
type character struct {
	token
	r rune
}

func NewCharacter(r rune) Token {
	return &character{
		token: token{ttype: TTCharacter},
		r:     r,
	}
}

func (c character) Equal(other Token) bool {
	if c.Type() != other.Type() {
		return false
	}

	o := other.(*character)
	return c.Rune() == o.Rune()
}

func (c character) String() string {
	return fmt.Sprintf("{character: %s flag: %s}", string(c.Rune()), c.Flag().String())
}

func (c character) Rune() rune {
	return c.r
}

// dot is any character. It implements Token.
type dot struct {
	token
}

func NewDot() Token {
	return &dot{
		token: token{ttype: TTDot},
	}
}

func (d dot) Equal(other Token) bool {
	if d.Type() != other.Type() {
		return false
	}

	return true
}

func (d dot) String() string {
	return fmt.Sprintf("{dot flag: %s}", d.Flag().String())
}

// set is a set of characters (similar to regexp character class).
// It implements Token.
type set struct {
	token
	runes map[rune]bool
}

func NewSet(runes []rune) Token {
	m := map[rune]bool{}
	for _, r := range runes {
		m[r] = true
	}
	return &set{
		token: token{ttype: TTSet},
		runes: m,
	}
}

func (s set) Equal(other Token) bool {
	if s.Type() != other.Type() {
		return false
	}

	o := other.(*set)
	r1, r2 := s.Runes(), o.Runes()

	if len(r1) != len(r2) {
		return false
	}

	for k, _ := range r1 {
		if _, ok := r2[k]; !ok {
			return false
		}
	}

	return true
}

func (s set) String() string {
	rs := make([]string, 0, 30)
	for r, _ := range s.Runes() {
		rs = append(rs, string(r))
	}
	return fmt.Sprintf("{set: %s flag: %s}", strings.Join(rs, ""), s.Flag().String())
}

func (s set) Runes() map[rune]bool {
	return s.runes
}
