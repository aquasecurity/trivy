package parser

import (
	"time"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/ast"
)

func NodeToRego(n *ast.Node, filePath string, offset int) any {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case ast.BoolNode, ast.IntNode, ast.FloatNode, ast.StringNode, ast.BinaryNode:
		return n.Value
	case ast.TimestampNode:
		t, ok := n.Value.(time.Time)
		if !ok {
			return nil
		}
		return t.Format(time.RFC3339)
	case ast.SequenceNode:
		v, ok := n.Value.([]*ast.Node)
		if !ok {
			return nil
		}
		return lo.Map(v, func(n *ast.Node, _ int) any {
			return NodeToRego(n, filePath, offset)
		})
	case ast.MappingNode:
		output := map[string]any{
			"__defsec_metadata": map[string]any{
				"startline": n.StartLine + offset,
				"endline":   n.EndLine + offset,
				"filepath":  filePath,
			},
		}
		v, ok := n.Value.(map[string]*ast.Node)
		if !ok {
			return output
		}

		for key, child := range v {
			output[key] = NodeToRego(child, filePath, offset)
		}
		return output
	}
	return nil
}
