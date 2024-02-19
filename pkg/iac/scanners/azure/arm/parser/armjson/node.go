package armjson

import "github.com/aquasecurity/trivy/pkg/iac/types"

type Node interface {
	Comments() []Node
	Range() Range
	Decode(target interface{}) error
	Kind() Kind
	Content() []Node
	Metadata() types.Metadata
}

type Range struct {
	Start Position
	End   Position
}

type Position struct {
	Line   int
	Column int
}

type node struct {
	raw      interface{}
	start    Position
	end      Position
	kind     Kind
	content  []Node
	comments []Node
	metadata *types.Metadata
	ref      string
}

func (n *node) Range() Range {
	return Range{
		Start: n.start,
		End: Position{
			Column: n.end.Column - 1,
			Line:   n.end.Line,
		},
	}
}

func (n *node) Comments() []Node {
	return n.comments
}

func (n *node) End() Position {
	return n.end
}

func (n *node) Kind() Kind {
	return n.kind
}

func (n *node) Content() []Node {
	return n.content
}
