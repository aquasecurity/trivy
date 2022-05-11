package jfather

import "fmt"

var nullRunes = []rune("null")

func (p *parser) parseNull() (Node, error) {

	n := p.newNode(KindNull)

	for _, expected := range nullRunes {
		if !p.swallowIfEqual(expected) {
			return nil, fmt.Errorf("unexpected character")
		}
	}
	n.raw = nil
	n.end = p.position
	return n, nil
}
