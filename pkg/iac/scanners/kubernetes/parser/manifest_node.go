package parser

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/log"
)

type TagType string

const (
	TagBool      TagType = "!!bool"
	TagInt       TagType = "!!int"
	TagFloat     TagType = "!!float"
	TagStr       TagType = "!!str"
	TagString    TagType = "!!string"
	TagSlice     TagType = "!!seq"
	TagMap       TagType = "!!map"
	TagTimestamp TagType = "!!timestamp"
	TagBinary    TagType = "!!binary"
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
	case TagBool, TagInt, TagFloat, TagString, TagStr, TagBinary:
		return r.Value
	case TagTimestamp:
		t, ok := r.Value.(time.Time)
		if !ok {
			return nil
		}
		return t.Format(time.RFC3339)
	case TagSlice:
		var output []any
		for _, node := range r.Value.([]*ManifestNode) {
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
		for key, node := range r.Value.(map[string]*ManifestNode) {
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
			return fmt.Errorf("failed to parse int: %w", err)
		}
		r.Value = val
	case TagFloat:
		val, err := strconv.ParseFloat(node.Value, 64)
		if err != nil {
			return fmt.Errorf("failed to parse float: %w", err)
		}
		r.Value = val
	case TagBool:
		val, err := strconv.ParseBool(node.Value)
		if err != nil {
			return fmt.Errorf("failed to parse bool: %w", err)
		}
		r.Value = val
	case TagTimestamp:
		var val time.Time
		if err := node.Decode(&val); err != nil {
			return fmt.Errorf("failed to decode timestamp: %w", err)
		}
		r.Value = val
	case TagBinary:
		val, err := base64.StdEncoding.DecodeString(node.Value)
		if err != nil {
			return fmt.Errorf("failed to decode binary data: %w", err)
		}
		r.Value = val
	case TagMap:
		return r.handleMapTag(node)
	case TagSlice:
		return r.handleSliceTag(node)
	default:
		log.WithPrefix("k8s").Debug("Skipping unsupported node tag",
			log.String("tag", node.Tag),
			log.FilePath(r.Path),
			log.Int("line", node.Line),
		)
	}
	return nil
}

func (r *ManifestNode) handleSliceTag(node *yaml.Node) error {
	var nodes []*ManifestNode
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
		nodes = append(nodes, newNode)
	}
	r.EndLine = maxLine
	r.Value = nodes
	return nil
}

func (r *ManifestNode) handleMapTag(node *yaml.Node) error {
	output := make(map[string]*ManifestNode)
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
			output[key] = newNode
			if newNode.EndLine > maxLine {
				maxLine = newNode.EndLine
			}
		}
	}
	r.EndLine = maxLine
	r.Value = output
	return nil
}
