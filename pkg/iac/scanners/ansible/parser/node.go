package parser

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
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

	switch node.Kind {
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!int":
			n.val, _ = strconv.Atoi(node.Value)
		case "!!float":
			// TODO: handle float properly
		case "!!bool":
			n.val, _ = strconv.ParseBool(node.Value)
		case "!!str", "!!string":
			n.val = node.Value
		}
		return nil
	case yaml.MappingNode:
		n.rng.startLine--
		childData, err := decodeMapNode(node)
		if err != nil {
			return err
		}
		n.val = childData
		return nil
	case yaml.SequenceNode:
		n.rng.startLine--
		childData, err := decodeSequenceNode(node)
		if err != nil {
			return err
		}
		n.val = childData
		return nil
	}
	return nil
}

func decodeMapNode(node *yaml.Node) (map[string]*Node, error) {
	childData := make(map[string]*Node, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		keyNode, valueNode := node.Content[i], node.Content[i+1]
		childNode, err := decodeChildNode(valueNode)
		if err != nil {
			return nil, err
		}
		childData[keyNode.Value] = &childNode
	}
	return childData, nil
}

func decodeSequenceNode(node *yaml.Node) ([]*Node, error) {
	childData := make([]*Node, 0, len(node.Content))
	for _, elemNode := range node.Content {
		childNode, err := decodeChildNode(elemNode)
		if err != nil {
			return nil, err
		}
		childData = append(childData, &childNode)
	}
	return childData, nil
}

func decodeChildNode(yNode *yaml.Node) (Node, error) {
	if yNode.Kind == yaml.ScalarNode && yNode.Tag == "!!null" {
		return Node{
			rng: rangeFromNode(yNode),
			val: nil,
		}, nil
	}

	var n Node
	if err := yNode.Decode(&n); err != nil {
		return Node{}, err
	}
	return n, nil
}

func (n *Node) initMetadata(fileSrc fsutils.FileSource, parent *iacTypes.Metadata, nodePath []string) {
	fsys, relPath := fileSrc.FSAndRelPath()
	ref := strings.Join(nodePath, ".")
	rng := iacTypes.NewRange(relPath, n.rng.startLine, n.rng.endLine, "", fsys)

	n.metadata = iacTypes.NewMetadata(rng, ref)
	n.metadata.SetParentPtr(parent)

	switch val := n.val.(type) {
	case map[string]*Node:
		for key, attr := range val {
			if attr == nil {
				continue
			}
			childPath := append(nodePath, key)
			attr.initMetadata(fileSrc, parent, childPath)
		}
	case []*Node:
		for idx, attr := range val {
			if attr == nil {
				continue
			}
			childPath := append(nodePath, fmt.Sprintf("[%d]", idx))
			attr.initMetadata(fileSrc, parent, childPath)
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
