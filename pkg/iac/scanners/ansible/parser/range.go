package parser

import "gopkg.in/yaml.v3"

type Range struct {
	Start   int
	EndLine int
}

// Covers returns true if 'r' fully contains 'other'.
func (r Range) Covers(other Range) bool {
	return r.Start <= other.Start && r.EndLine >= other.EndLine
}

func (r Range) Overlaps(o Range) bool {
	return r.Start < o.EndLine && o.Start < r.EndLine
}

func rangeFromNode(node *yaml.Node) Range {
	return Range{
		Start:   node.Line,
		EndLine: calculateEndLine(node),
	}
}

func calculateEndLine(node *yaml.Node) int {
	for node.Content != nil {
		node = node.Content[len(node.Content)-1]
	}
	return node.Line
}
