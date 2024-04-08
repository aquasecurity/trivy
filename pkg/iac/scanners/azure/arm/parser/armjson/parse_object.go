package armjson

import (
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func (p *parser) parseObject(parentMetadata *types.Metadata) (Node, error) {

	n, metadata := p.newNode(KindObject, parentMetadata)

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

	var nextComments []Node
	return p.iterateObject(nextComments, metadata, n)

}

// nolint: gocyclo
func (p *parser) iterateObject(nextComments []Node, metadata *types.Metadata, n *node) (Node, error) {
	for {

		if err := p.parseWhitespace(); err != nil {
			return nil, err
		}

		comments := make([]Node, len(nextComments))
		copy(comments, nextComments)
		nextComments = nil
		for {
			peeked, err := p.peeker.Peek()
			if err != nil {
				return nil, err
			}
			if peeked != '/' {
				break
			}
			comment, err := p.parseComment(metadata)
			if err != nil {
				return nil, err
			}
			comments = append(comments, comment)
		}

		if comments != nil {
			if err := p.parseWhitespace(); err != nil {
				return nil, err
			}
		}

		key, err := p.parseString(metadata)
		if err != nil {
			return nil, err
		}

		if err := p.parseWhitespace(); err != nil {
			return nil, err
		}

		if !p.swallowIfEqual(':') {
			return nil, p.makeError("invalid character, expecting ':'")
		}

		val, err := p.parseElement(metadata)
		if err != nil {
			return nil, err
		}
		ref := key.(*node).raw.(string)
		key.(*node).ref = ref
		val.(*node).ref = ref

		for {
			peeked, err := p.peeker.Peek()
			if err != nil {
				return nil, err
			}
			if peeked != '/' {
				break
			}
			comment, err := p.parseComment(metadata)
			if err != nil {
				return nil, err
			}
			comments = append(comments, comment)
		}

		// we've hit the end of the object
		if p.swallowIfEqual('}') {
			key.(*node).comments = comments
			val.(*node).comments = comments
			n.content = append(n.content, key, val)
			n.end = p.position
			return n, nil
		}

		if !p.swallowIfEqual(',') {
			return nil, p.makeError("unexpected character - expecting , or }")
		}

		for {
			if err := p.parseWhitespace(); err != nil {
				return nil, err
			}
			peeked, err := p.peeker.Peek()
			if err != nil {
				return nil, err
			}
			if peeked != '/' {
				break
			}
			comment, err := p.parseComment(metadata)
			if err != nil {
				return nil, err
			}
			if comment.Range().Start.Line > val.Range().End.Line {
				nextComments = append(nextComments, comment)
			} else {
				comments = append(comments, comment)
			}
		}

		key.(*node).comments = comments
		val.(*node).comments = comments
		n.content = append(n.content, key, val)

	}
}
