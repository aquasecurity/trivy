package jfather

import (
	"fmt"
	"strconv"
)

func (p *parser) parseNumber() (Node, error) {
	n := p.newNode(KindNumber)

	var str string

	if p.swallowIfEqual('-') {
		str = "-"
	}

	integral, err := p.parseIntegral()
	if err != nil {
		return nil, err
	}
	fraction, err := p.parseFraction()
	if err != nil {
		return nil, err
	}
	exponent, err := p.parseExponent()
	if err != nil {
		return nil, err
	}

	str = fmt.Sprintf("%s%s%s%s", str, integral, fraction, exponent)
	n.end = p.position

	if fraction != "" || exponent != "" {
		f, err := strconv.ParseFloat(str, 64)
		if err != nil {
			return nil, p.makeError("%s", err)
		}
		n.raw = f
		return n, nil
	}

	i, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return nil, p.makeError("%s", err)
	}
	n.raw = i

	return n, nil
}

func (p *parser) parseIntegral() (string, error) {
	r, err := p.next()
	if err != nil {
		return "", err
	}
	if r == '0' {
		r, _ := p.peeker.Peek()
		if r >= '0' && r <= '9' {
			return "", p.makeError("invalid number")
		}
		return "0", nil
	}

	var str string
	if r < '1' || r > '9' {
		return "", p.makeError("invalid number")
	}
	str += string(r)

	for {
		r, err := p.next()
		if err != nil {
			return str, nil
		}
		if r < '0' || r > '9' {
			return str, p.undo()
		}
		str += string(r)
	}
}

func (p *parser) parseFraction() (string, error) {
	r, err := p.next()
	if err != nil {
		return "", nil
	}
	if r != '.' {
		return "", p.undo()
	}

	str := "."

	for {
		r, err := p.next()
		if err != nil {
			break
		}
		if r < '0' || r > '9' {
			if err := p.undo(); err != nil {
				return "", err
			}
			break
		}
		str += string(r)
	}

	if str == "." {
		return "", p.makeError("invalid number - missing digits after decimal point")
	}

	return str, nil
}

func (p *parser) parseExponent() (string, error) {
	r, err := p.next()
	if err != nil {
		return "", nil
	}
	if r != 'e' && r != 'E' {
		return "", p.undo()
	}

	str := string(r)

	r, err = p.next()
	if err != nil {
		return "", nil
	}
	hasDigits := r >= '0' && r <= '9'
	if r != '-' && r != '+' && !hasDigits {
		return "", p.undo()
	}
	str += string(r)

	for {
		r, err := p.next()
		if err != nil {
			break
		}
		if r < '0' || r > '9' {
			if err := p.undo(); err != nil {
				return "", err
			}
			break
		}
		hasDigits = true
		str += string(r)
	}

	if !hasDigits {
		return "", p.makeError("invalid number - no digits in exponent")
	}

	return str, nil
}
