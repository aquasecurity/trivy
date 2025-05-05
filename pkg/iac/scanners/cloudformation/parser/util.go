package parser

import (
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes/parser"
)

func setPropertyValueFromYaml(node *yaml.Node, propertyData *Property) error {
	if IsIntrinsicFunc(node) {
		var newContent []*yaml.Node

		newContent = append(newContent, &yaml.Node{
			Tag:   "!!str",
			Value: getIntrinsicTag(node.Tag),
			Kind:  yaml.ScalarNode,
		})

		newContent = createNode(node, newContent)

		node.Tag = string(parser.TagMap)
		node.Kind = yaml.MappingNode
		node.Content = newContent
	}

	if node.Content == nil {

		switch node.Tag {
		case "!!int":
			propertyData.Type = cftypes.Int
			propertyData.Value, _ = strconv.Atoi(node.Value)
		case "!!bool":
			propertyData.Type = cftypes.Bool
			propertyData.Value, _ = strconv.ParseBool(node.Value)
		case "!!float":
			propertyData.Type = cftypes.Float64
			propertyData.Value, _ = strconv.ParseFloat(node.Value, 64)
		case "!!str", "!!string":
			propertyData.Type = cftypes.String
			propertyData.Value = node.Value
		}
		return nil
	}

	switch node.Tag {
	case string(parser.TagMap):
		var childData map[string]*Property
		if err := node.Decode(&childData); err != nil {
			return err
		}
		propertyData.Type = cftypes.Map
		propertyData.Value = childData
		return nil
	case "!!seq":
		var childData []*Property
		if err := node.Decode(&childData); err != nil {
			return err
		}
		propertyData.Type = cftypes.List
		propertyData.Value = childData
		return nil
	}

	return nil
}

func createNode(node *yaml.Node, newContent []*yaml.Node) []*yaml.Node {
	if node.Content == nil {
		newContent = append(newContent, &yaml.Node{
			Tag:   "!!str",
			Value: node.Value,
			Kind:  yaml.ScalarNode,
		})
	} else {

		newNode := &yaml.Node{
			Content: node.Content,
			Kind:    node.Kind,
		}

		switch node.Kind {
		case yaml.SequenceNode:
			newNode.Tag = "!!seq"
		case yaml.MappingNode:
			newNode.Tag = string(parser.TagMap)
		case yaml.ScalarNode:
		default:
			newNode.Tag = node.Tag
		}
		newContent = append(newContent, newNode)
	}
	return newContent
}

func calculateEndLine(node *yaml.Node) int {
	if node.Content == nil {
		return node.Line
	}

	return calculateEndLine(node.Content[len(node.Content)-1])
}
