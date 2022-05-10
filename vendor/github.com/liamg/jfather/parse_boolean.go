package jfather

import "fmt"

var trueRunes = []rune("true")
var falseRunes = []rune("false")

func (p *parser) parseBoolean() (Node, error) {

	n := p.newNode(KindBoolean)

	r, err := p.peeker.Peek()
	if err != nil {
		return nil, err
	}

	if r == 't' {
		for _, expected := range trueRunes {
			if !p.swallowIfEqual(expected) {
				return nil, fmt.Errorf("unexpected character in boolean value")
			}
		}
		n.raw = true
		n.end = p.position
		return n, nil
	}

	for _, expected := range falseRunes {
		if !p.swallowIfEqual(expected) {
			return nil, fmt.Errorf("unexpected character in boolean value")
		}
	}
	n.raw = false
	n.end = p.position
	return n, nil
}
