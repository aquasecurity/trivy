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
	TagFloat  TagType = "!!float"
	TagStr    TagType = "!!str"
	TagString TagType = "!!string"
	TagSlice  TagType = "!!seq"
	TagMap    TagType = "!!map"
)

type ManifestNode struct {
	StartLine int
	EndLine   int
	Offset    int
	Value     any
	Type      TagType
	Path      string
}

func (r *ManifestNode) ToRego() any {
	if r == nil {
		return nil
	}
	switch r.Type {
	case TagBool, TagInt, TagString, TagStr:
		return r.Value
	case TagSlice:
		var output []any
		for _, node := range r.Value.([]ManifestNode) {
			output = append(output, node.ToRego())
		}
		return output
	case TagMap:
		output := make(map[string]any)
		output["__defsec_metadata"] = map[string]any{
			"startline": r.StartLine,
			"endline":   r.EndLine,
			"filepath":  r.Path,
			"offset":    r.Offset,
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
	case TagString, TagStr:

		r.Value = node.Value
	case TagInt:
		val, err := strconv.Atoi(node.Value)
		if err != nil {
			return err
		}
		r.Value = val
	case TagFloat:
		val, err := strconv.ParseFloat(node.Value, 64)
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
		return r.handleMapTag(node)
	case TagSlice:
		return r.handleSliceTag(node)

	default:
		return fmt.Errorf("node tag is not supported %s", node.Tag)
	}
	return nil
}

func (r *ManifestNode) handleSliceTag(node *yaml.Node) error {
	var nodes []ManifestNode
	maxLine := node.Line
	for _, contentNode := range node.Content {
		newNode := new(ManifestNode)
		newNode.Path = r.Path
		if err := contentNode.Decode(newNode); err != nil {
			return err
		}
		if newNode.EndLine > maxLine {
			maxLine = newNode.EndLine
		}
		nodes = append(nodes, *newNode)
	}
	r.EndLine = maxLine
	r.Value = nodes
	return nil
}

func (r *ManifestNode) handleMapTag(node *yaml.Node) error {
	output := make(map[string]ManifestNode)
	var key string
	maxLine := node.Line
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
			if newNode.EndLine > maxLine {
				maxLine = newNode.EndLine
			}
		}
	}
	r.EndLine = maxLine
	r.Value = output
	return nil
}
