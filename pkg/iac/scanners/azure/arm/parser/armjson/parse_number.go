package armjson

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func (p *parser) parseNumber(parentMetadata *types.Metadata) (Node, error) {

	n, _ := p.newNode(KindNumber, parentMetadata)

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

	var sb strings.Builder
	if r < '1' || r > '9' {
		return "", p.makeError("invalid number")
	}
	sb.WriteRune(r)

	for {
		r, err := p.next()
		if err != nil {
			return sb.String(), nil
		}
		if r < '0' || r > '9' {
			return sb.String(), p.undo()
		}
		sb.WriteRune(r)
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

	var sb strings.Builder
	sb.WriteRune('.')

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
		sb.WriteRune(r)
	}

	str := sb.String()
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

	var sb strings.Builder
	sb.WriteRune(r)

	r, err = p.next()
	if err != nil {
		return "", nil
	}
	hasDigits := r >= '0' && r <= '9'
	if r != '-' && r != '+' && !hasDigits {
		return "", p.undo()
	}

	sb.WriteRune(r)

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
		sb.WriteRune(r)
	}

	if !hasDigits {
		return "", p.makeError("invalid number - no digits in exponent")
	}

	return sb.String(), nil
}
