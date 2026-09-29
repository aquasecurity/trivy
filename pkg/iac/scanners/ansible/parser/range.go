package parser

import "gopkg.in/yaml.v3"

type Range struct {
	Start int
	End   int
}

// Covers returns true if 'r' fully contains 'other'.
func (r Range) Covers(other Range) bool {
	return r.Start <= other.Start && r.End >= other.End
}

func (r Range) Overlaps(o Range) bool {
	return r.Start < o.End && o.Start < r.End
}

func rangeFromNode(node *yaml.Node) Range {
	return Range{
		Start: node.Line,
		End:   calculateEndLine(node),
	}
}

func calculateEndLine(node *yaml.Node) int {
	for node.Content != nil {
		node = node.Content[len(node.Content)-1]
	}
	return node.Line
}
