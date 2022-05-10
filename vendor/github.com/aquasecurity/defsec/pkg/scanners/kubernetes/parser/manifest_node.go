package parser

import (
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
)

type TagType string

const (
	TagBool   TagType = "!!bool"
	TagInt    TagType = "!!int"
	TagString TagType = "!!str"
	TagSlice  TagType = "!!seq"
	TagMap    TagType = "!!map"
)

type ManifestNode struct {
	StartLine int
	EndLine   int
	Value     interface{}
	Type      TagType
	Path      string
}

func (r *ManifestNode) ToRego() interface{} {
	if r == nil {
		return nil
	}
	switch r.Type {
	case TagBool, TagInt, TagString:
		return r.Value
	case TagSlice:
		var output []interface{}
		for _, node := range r.Value.([]ManifestNode) {
			output = append(output, node.ToRego())
		}
		return output
	case TagMap:
		output := make(map[string]interface{})
		output["__defsec_metadata"] = map[string]interface{}{
			"startline": r.StartLine,
			"endline":   r.EndLine,
			"filepath":  r.Path,
		}
		for key, node := range r.Value.(map[string]ManifestNode) {
			output[key] = node.ToRego()
		}
		return output
	}
	return nil
}

func (r *ManifestNode) UnmarshalYAML(node *yaml.Node) error {

	r.StartLine = node.Line
	r.EndLine = node.Line
	r.Type = TagType(node.Tag)

	switch TagType(node.Tag) {
	case TagString:
		r.Value = node.Value
	case TagInt:
		val, err := strconv.Atoi(node.Value)
		if err != nil {
			return err
		}
		r.Value = val
	case TagBool:
		val, err := strconv.ParseBool(node.Value)
		if err != nil {
			return err
		}
		r.Value = val
	case TagMap:
		output := make(map[string]ManifestNode)
		var key string
		max := node.Line
		for i, contentNode := range node.Content {
			if i == 0 || i%2 == 0 {
				key = contentNode.Value
			} else {
				newNode := new(ManifestNode)
				newNode.Path = r.Path
				if err := contentNode.Decode(newNode); err != nil {
					return err
				}
				output[key] = *newNode
				if newNode.EndLine > max {
					max = newNode.EndLine
				}
			}
		}
		r.EndLine = max
		r.Value = output
	case TagSlice:
		var nodes []ManifestNode
		max := node.Line
		for _, contentNode := range node.Content {
			newNode := new(ManifestNode)
			newNode.Path = r.Path
			if err := contentNode.Decode(newNode); err != nil {
				return err
			}
			if newNode.EndLine > max {
				max = newNode.EndLine
			}
			nodes = append(nodes, *newNode)
		}
		r.EndLine = max
		r.Value = nodes
	default:
		return fmt.Errorf("node tag is not supported %s", node.Tag)
	}
	return nil
}
