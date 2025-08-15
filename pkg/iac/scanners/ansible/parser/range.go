package parser

import "gopkg.in/yaml.v3"

type Range struct {
	startLine int
	endLine   int
}

func rangeFromNode(node *yaml.Node) Range {
	return Range{
		startLine: node.Line,
		endLine:   calculateEndLine(node),
	}
}

func calculateEndLine(node *yaml.Node) int {
	for node.Content != nil {
		node = node.Content[len(node.Content)-1]
	}
	return node.Line
}
