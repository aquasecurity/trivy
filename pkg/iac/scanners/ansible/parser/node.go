package parser

import (
	"io/fs"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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

	switch val := n.val.(type) {
	case map[string]*Node:
		for _, attr := range val {
			if attr == nil {
				continue
			}
			attr.initMetadata(fsys, parent, path)
		}
	case []*Node:
		for _, attr := range val {
			if attr == nil {
				continue
			}
			attr.initMetadata(fsys, parent, path)
		}
	}
}

func (n *Node) Render(variables vars.Vars) (*Node, error) {
	if n == nil {
		return nil, nil
	}

	switch v := n.val.(type) {
	case string:
		rendered, err := evaluateTemplate(v, variables)
		if err != nil {
			return nil, err
		}
		return n.withValue(rendered), nil
	case map[string]*Node:
		renderedMap := make(map[string]*Node)
		for key, val := range v {
			r, err := val.Render(variables)
			if err != nil {
				return nil, err
			}
			renderedMap[key] = r
		}
		return n.withValue(renderedMap), nil
	case []*Node:
		var renderedList []*Node
		for _, val := range v {
			r, err := val.Render(variables)
			if err != nil {
				return nil, err
			}
			renderedList = append(renderedList, r)
		}
		return n.withValue(renderedList), nil
	default:
		return n, nil
	}
}

func (n *Node) withValue(val any) *Node {
	return &Node{val: val, rng: n.rng, metadata: n.metadata}
}
