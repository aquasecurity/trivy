package ast

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/x/json"
)

const mapTag = "!!map"

func isCustomTag(tag string) bool {
	return strings.HasPrefix(tag, "!") && !strings.HasPrefix(tag, "!!")
}

func (n *Node) UnmarshalYAML(node *yaml.Node) error {
	n.StartLine = node.Line
	n.EndLine = calculateEndLine(node)

	if isCustomTag(node.Tag) {
		var newContent []*yaml.Node

		newContent = append(newContent, &yaml.Node{
			Tag:   "!!str",
			Value: getIntrinsicTag(node.Tag),
			Kind:  yaml.ScalarNode,
		})

		newContent = createNode(node, newContent)

		node.Tag = mapTag
		node.Kind = yaml.MappingNode
		node.Content = newContent
	}

	switch node.Tag {
	case "!!string", "!!str":
		n.Value = node.Value
		n.Kind = StringNode
	case "!!int":
		val, err := strconv.Atoi(node.Value)
		if err != nil {
			return fmt.Errorf("failed to parse int: %w", err)
		}
		n.Value = val
		n.Kind = IntNode
	case "!!float":
		val, err := strconv.ParseFloat(node.Value, 64)
		if err != nil {
			return fmt.Errorf("failed to parse float: %w", err)
		}
		n.Value = val
		n.Kind = FloatNode
	case "!!bool":
		val, err := strconv.ParseBool(node.Value)
		if err != nil {
			return fmt.Errorf("failed to parse bool: %w", err)
		}
		n.Value = val
		n.Kind = BoolNode
	case "!!timestamp":
		var val time.Time
		if err := node.Decode(&val); err != nil {
			return fmt.Errorf("failed to decode timestamp: %w", err)
		}
		n.Value = val
		n.Kind = TimestampNode
	case "!!binary":
		val, err := base64.StdEncoding.DecodeString(node.Value)
		if err != nil {
			return fmt.Errorf("failed to decode binary data: %w", err)
		}
		n.Value = val
		n.Kind = BinaryNode
	case mapTag:
		entries, err := handleMapTag(node)
		if err != nil {
			return err
		}
		n.Kind = MappingNode
		n.Value = entries
		return nil
	case "!!seq":
		var items []*Node
		if err := node.Decode(&items); err != nil {
			return err
		}
		n.Kind = SequenceNode
		n.Value = items
		return nil
	default:
		log.WithPrefix("k8s").Debug("Skipping unsupported node tag",
			log.String("tag", node.Tag),
			log.Int("line", node.Line),
		)
	}
	return nil
}

// TODO: use custom unmarshaller
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
			newNode.Tag = mapTag
		case yaml.ScalarNode:
		default:
			newNode.Tag = node.Tag
		}
		newContent = append(newContent, newNode)
	}
	return newContent
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

func handleMapTag(node *yaml.Node) (map[string]*Node, error) {
	output := make(map[string]*Node)
	var key string
	for i, content := range node.Content {
		if i == 0 || i%2 == 0 {
			key = content.Value
		} else {
			var child Node
			if content.Tag == "!!null" {
				child = Node{
					Kind:  NullNode,
					Value: nil,
					Location: json.Location{
						StartLine: content.Line,
						EndLine:   content.Line,
					},
				}
			} else {
				if err := content.Decode(&child); err != nil {
					return nil, err
				}
			}

			output[key] = &child
		}
	}
	return output, nil
}

func calculateEndLine(node *yaml.Node) int {
	if node.Content == nil {
		return node.Line
	}
	return calculateEndLine(node.Content[len(node.Content)-1])
}
