package jfather

func (p *parser) parseObject() (Node, error) {

	n := p.newNode(KindObject)
	c, err := p.next()
	if err != nil {
		return nil, err
	}

	if c != '{' {
		return nil, p.makeError("expecting object delimiter")
	}

	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}

	// we've hit the end of the object
	if p.swallowIfEqual('}') {
		n.end = p.position
		return n, nil
	}

	// for each key/val
	for {

		if err := p.parseWhitespace(); err != nil {
			return nil, err
		}

		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		n.content = append(n.content, key)

		if err := p.parseWhitespace(); err != nil {
			return nil, err
		}

		if !p.swallowIfEqual(':') {
			return nil, p.makeError("invalid character, expecting ':'")
		}

		val, err := p.parseElement()
		if err != nil {
			return nil, err
		}
		n.content = append(n.content, val)

		// we've hit the end of the object
		if p.swallowIfEqual('}') {
			n.end = p.position
			return n, nil
		}

		if !p.swallowIfEqual(',') {
			return nil, p.makeError("unexpected character - expecting , or }")
		}
	}

}
