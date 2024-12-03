package armjson

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

var nullRunes = []rune("null")

func (p *parser) parseNull(parentMetadata *types.Metadata) (Node, error) {

	n, _ := p.newNode(KindNull, parentMetadata)

	for _, expected := range nullRunes {
		if !p.swallowIfEqual(expected) {
			return nil, fmt.Errorf("unexpected character")
		}
	}
	n.raw = nil
	n.end = p.position
	return n, nil
}
