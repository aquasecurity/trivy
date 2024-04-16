package armjson

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func (p *parser) parseComment(parentMetadata *types.Metadata) (Node, error) {

	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}

	_, err := p.next()
	if err != nil {
		return nil, err
	}

	b, err := p.next()
	if err != nil {
		return nil, err
	}

	switch b {
	case '/':
		return p.parseLineComment(parentMetadata)
	case '*':
		return p.parseBlockComment(parentMetadata)
	default:
		return nil, p.makeError("expecting comment delimiter")
	}
}

func (p *parser) parseLineComment(parentMetadata *types.Metadata) (Node, error) {

	n, _ := p.newNode(KindComment, parentMetadata)

	var sb strings.Builder
	for {
		c, err := p.next()
		if err != nil {
			return nil, err
		}
		if c == '\n' {
			p.position.Column = 1
			p.position.Line++
			break
		}
		sb.WriteRune(c)
	}

	n.raw = sb.String()
	n.end = p.position

	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}
	return n, nil
}

func (p *parser) parseBlockComment(parentMetadata *types.Metadata) (Node, error) {

	n, _ := p.newNode(KindComment, parentMetadata)

	var sb strings.Builder

	for {
		c, err := p.next()
		if err != nil {
			return nil, err
		}
		if c == '*' {
			c, err := p.peeker.Peek()
			if err != nil {
				return nil, err
			}
			if c == '/' {
				break
			}
			sb.WriteRune('*')
		} else {
			if c == '\n' {
				p.position.Column = 1
				p.position.Line++
			}
			sb.WriteRune(c)
		}
	}

	n.raw = sb.String()

	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}

	return n, nil
}
