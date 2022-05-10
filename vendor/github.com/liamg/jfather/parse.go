package jfather

import (
	"fmt"
)

type parser struct {
	position Position
	size     int
	peeker   *PeekReader
}

func newParser(p *PeekReader, pos Position) *parser {
	return &parser{
		position: pos,
		peeker:   p,
	}
}

func (p *parser) parse() (Node, error) {
	return p.parseElement()
}

func (p *parser) parseElement() (Node, error) {
	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}
	n, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}
	return n, nil
}

func (p *parser) parseValue() (Node, error) {
	c, err := p.peeker.Peek()
	if err != nil {
		return nil, err
	}

	switch c {
	case '"':
		return p.parseString()
	case '{':
		return p.parseObject()
	case '[':
		return p.parseArray()
	case 'n':
		return p.parseNull()
	case 't', 'f':
		return p.parseBoolean()
	default:
		if c == '-' || (c >= '0' && c <= '9') {
			return p.parseNumber()
		}
		return nil, fmt.Errorf("unexpected character '%c'", c)
	}
}

func (p *parser) next() (rune, error) {
	b, err := p.peeker.Next()
	if err != nil {
		return 0, err
	}
	p.position.Column++
	p.size++
	return b, nil
}

func (p *parser) undo() error {
	if err := p.peeker.Undo(); err != nil {
		return err
	}
	p.position.Column--
	p.size--
	return nil
}

func (p *parser) makeError(format string, args ...interface{}) error {
	return fmt.Errorf(
		"error at line %d, column %d: %s",
		p.position.Line,
		p.position.Column,
		fmt.Sprintf(format, args...),
	)
}

func (p *parser) newNode(k Kind) *node {
	return &node{
		start: p.position,
		kind:  k,
	}
}

func (p *parser) swallowIfEqual(r rune) bool {
	c, err := p.peeker.Peek()
	if err != nil {
		return false
	}
	if c != r {
		return false
	}
	_, _ = p.next()
	return true
}
