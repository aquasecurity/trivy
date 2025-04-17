package parser

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// The transformFuncNodes function transforms CloudFormation function nodes (such as !Ref or !Join)
// into mapping nodes, where the function tags are replaced by the corresponding CloudFormation structures,
// for example, !Ref is converted to { “Fn::Ref”: “some-value” }.
//
// This is necessary because the yaml package interprets CloudFormation functions as custom tags,
// and the function is required to convert these tags into a structure suitable for further processing and use.
func transformFuncNodes(node *yaml.Node) {
	if IsIntrinsicFunc(node) {
		// node: !Tag some-value -> node: { "Fn::Tag": "some-value" }
		node.Content = []*yaml.Node{
			{
				Tag:   "!!str",
				Value: getIntrinsicTag(node.Tag),
				Kind:  yaml.ScalarNode,
			},
			createNode(node),
		}
		node.Tag = "!!map"
		node.Kind = yaml.MappingNode
		transformFuncNodes(node)
		return
	}

	for _, child := range node.Content {
		transformFuncNodes(child)
	}
}

func createNode(node *yaml.Node) *yaml.Node {
	if node.Content == nil {
		return &yaml.Node{
			Tag:   "!!str",
			Value: node.Value,
			Kind:  yaml.ScalarNode,
		}
	}

	newNode := &yaml.Node{
		Kind:    node.Kind,
		Content: node.Content,
	}

	switch node.Kind {
	case yaml.SequenceNode:
		newNode.Tag = "!!seq"
	case yaml.MappingNode:
		newNode.Tag = "!!map"
	default:
		newNode.Tag = node.Tag
	}

	return newNode
}

func getIntrinsicTag(tag string) string {
	tag = strings.TrimPrefix(tag, "!")
	switch tag {
	case "Ref", "Contains":
		return tag
	default:
		return fmt.Sprintf("Fn::%s", tag)
	}
}
