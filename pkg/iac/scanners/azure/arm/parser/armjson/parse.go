package armjson

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/types"
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

func (p *parser) parse(rootMetadata *types.Metadata) (Node, error) {
	root, err := p.parseElement(rootMetadata)
	if err != nil {
		return nil, err
	}
	root.(*node).updateMetadata("")
	return root, nil
}

func (p *parser) parseElement(parentMetadata *types.Metadata) (Node, error) {
	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}
	n, err := p.parseValue(parentMetadata)
	if err != nil {
		return nil, err
	}
	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}
	return n, nil
}

func (p *parser) parseValue(parentMetadata *types.Metadata) (Node, error) {
	c, err := p.peeker.Peek()
	if err != nil {
		return nil, err
	}

	switch c {
	case '/':
		return p.parseComment(parentMetadata)
	case '"':
		return p.parseString(parentMetadata)
	case '{':
		return p.parseObject(parentMetadata)
	case '[':
		return p.parseArray(parentMetadata)
	case 'n':
		return p.parseNull(parentMetadata)
	case 't', 'f':
		return p.parseBoolean(parentMetadata)
	default:
		if c == '-' || (c >= '0' && c <= '9') {
			return p.parseNumber(parentMetadata)
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

func (p *parser) makeError(format string, args ...any) error {
	return fmt.Errorf(
		"error at line %d, column %d: %s",
		p.position.Line,
		p.position.Column,
		fmt.Sprintf(format, args...),
	)
}

func (p *parser) newNode(k Kind, parentMetadata *types.Metadata) (*node, *types.Metadata) {
	n := &node{
		start: p.position,
		kind:  k,
	}
	metadata := types.NewMetadata(
		types.NewRange(parentMetadata.Range().GetFilename(), n.start.Line, n.end.Line, "", parentMetadata.Range().GetFS()),
		n.ref,
	)
	metadata.SetParentPtr(parentMetadata)
	n.metadata = &metadata
	return n, n.metadata
}

func (n *node) updateMetadata(prefix string) {

	var full string
	// nolint:gocritic
	if strings.HasPrefix(n.ref, "[") {
		full = prefix + n.ref
	} else if prefix != "" {
		full = prefix + "." + n.ref
	} else {
		full = n.ref
	}

	n.metadata.SetRange(types.NewRange(n.metadata.Range().GetFilename(),
		n.start.Line,
		n.end.Line,
		"",
		n.metadata.Range().GetFS()))

	n.metadata.SetReference(full)

	for i := range n.content {
		n.content[i].(*node).updateMetadata(full)
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
