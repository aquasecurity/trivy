package parser

import "gopkg.in/yaml.v3"

type Range struct {
	StartLine int
	EndLine   int
}

// Covers returns true if 'r' fully contains 'other'.
func (r Range) Covers(other Range) bool {
	return r.StartLine <= other.StartLine && r.EndLine >= other.EndLine
}

func rangeFromNode(node *yaml.Node) Range {
	return Range{
		StartLine: node.Line,
		EndLine:   calculateEndLine(node),
	}
}

func calculateEndLine(node *yaml.Node) int {
	for node.Content != nil {
		node = node.Content[len(node.Content)-1]
	}
	return node.Line
}
