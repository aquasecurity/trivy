package armjson

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func (p *parser) parseArray(parentMetadata *types.Metadata) (Node, error) {
	n, metadata := p.newNode(KindArray, parentMetadata)

	c, err := p.next()
	if err != nil {
		return nil, err
	}

	if c != '[' {
		return nil, p.makeError("expecting object delimiter")
	}
	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}
	// we've hit the end of the object
	if p.swallowIfEqual(']') {
		n.end = p.position
		return n, nil
	}

	// for each element
	for {

		if err := p.parseWhitespace(); err != nil {
			return nil, err
		}

		val, err := p.parseElement(metadata)
		if err != nil {
			return nil, err
		}
		val.(*node).ref = fmt.Sprintf("[%d]", len(n.content))

		n.content = append(n.content, val)

		// we've hit the end of the array
		if p.swallowIfEqual(']') {
			n.end = p.position
			return n, nil
		}

		if !p.swallowIfEqual(',') {
			return nil, p.makeError("unexpected character - expecting , or ]")
		}
	}
}
