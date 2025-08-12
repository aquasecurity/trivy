package parser

import (
	"io/fs"
	"strconv"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"gopkg.in/yaml.v3"
)

type Node struct {
	rng      Range
	metadata iacTypes.Metadata
	val      any
}

func (n *Node) UnmarshalYAML(node *yaml.Node) error {
	n.rng = rangeFromNode(node)

	// TODO: parse null node

	if node.Content == nil {
		switch node.Tag {
		case "!!int":
			n.val, _ = strconv.Atoi(node.Value)
		case "!!bool":
			n.val, _ = strconv.ParseBool(node.Value)
		case "!!str", "!!string":
			n.val = node.Value
		}
		return nil
	}

	switch node.Tag {
	case "!!map":
		n.rng.startLine--
		var childData map[string]*Node
		if err := node.Decode(&childData); err != nil {
			return err
		}
		n.val = childData
		return nil
	case "!!seq":
		n.rng.startLine--
		var childData []*Node
		if err := node.Decode(&childData); err != nil {
			return err
		}
		n.val = childData
		return nil
	}
	return nil
}

func (n *Node) initMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	n.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, n.rng.startLine, n.rng.endLine, "", fsys),
		// TODO: use node path as reference
		"",
	)
	n.metadata.SetParentPtr(parent)

	switch n.val.(type) {
	case map[string]*Node:
		for _, attr := range n.val.(map[string]*Node) {
			if attr == nil {
				continue
			}
			attr.initMetadata(fsys, parent, path)
		}
	case []*Node:
		for _, attr := range n.val.([]*Node) {
			if attr == nil {
				continue
			}
			attr.initMetadata(fsys, parent, path)
		}
	}
}

func (n *Node) Render(vars Vars) (*Node, error) {
	if n == nil {
		return n, nil
	}

	switch v := n.val.(type) {
	case string:
		rendered, err := evaluateTemplate(v, vars)
		if err != nil {
			return nil, err
		}
		return &Node{val: rendered, rng: n.rng, metadata: n.metadata}, nil
	case map[string]*Node:
		renderedMap := make(map[string]*Node)
		for key, val := range v {
			r, err := val.Render(vars)
			if err != nil {
				return nil, err
			}
			renderedMap[key] = r
		}
		return &Node{val: renderedMap, rng: n.rng, metadata: n.metadata}, nil
	case []*Node:
		var renderedList []*Node
		for _, val := range v {
			r, err := val.Render(vars)
			if err != nil {
				return nil, err
			}
			renderedList = append(renderedList, r)
		}
		return &Node{val: renderedList, rng: n.rng, metadata: n.metadata}, nil
	default:
		return n, nil
	}
}
