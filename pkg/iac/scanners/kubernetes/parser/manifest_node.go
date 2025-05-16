package parser

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/log"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
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
	xjson.Location
	Offset int
	Value  any
	Type   TagType
	Path   string
}

func (n *ManifestNode) ToRego() any {
	if n == nil {
		return nil
	}
	switch n.Type {
	case TagBool, TagInt, TagFloat, TagString, TagStr, TagBinary:
		return n.Value
	case TagTimestamp:
		t, ok := n.Value.(time.Time)
		if !ok {
			return nil
		}
		return t.Format(time.RFC3339)
	case TagSlice:
		var output []any
		for _, node := range n.Value.([]*ManifestNode) {
			output = append(output, node.ToRego())
		}
		return output
	case TagMap:
		output := map[string]any{
			"__defsec_metadata": n.metadata(),
		}
		for key, node := range n.Value.(map[string]*ManifestNode) {
			output[key] = node.ToRego()
		}
		return output
	}
	return nil
}

func (n *ManifestNode) metadata() map[string]any {
	return map[string]any{
		"startline": n.StartLine,
		"endline":   n.EndLine,
		"filepath":  n.Path,
		"offset":    n.Offset,
	}
}

func (n *ManifestNode) UnmarshalYAML(node *yaml.Node) error {
	n.StartLine = node.Line
	n.EndLine = node.Line
	n.Type = TagType(node.Tag)

	switch TagType(node.Tag) {
	case TagString, TagStr:
		n.Value = node.Value
	case TagInt:
		val, err := strconv.Atoi(node.Value)
		if err != nil {
			return fmt.Errorf("failed to parse int: %w", err)
		}
		n.Value = val
	case TagFloat:
		val, err := strconv.ParseFloat(node.Value, 64)
		if err != nil {
			return fmt.Errorf("failed to parse float: %w", err)
		}
		n.Value = val
	case TagBool:
		val, err := strconv.ParseBool(node.Value)
		if err != nil {
			return fmt.Errorf("failed to parse bool: %w", err)
		}
		n.Value = val
	case TagTimestamp:
		var val time.Time
		if err := node.Decode(&val); err != nil {
			return fmt.Errorf("failed to decode timestamp: %w", err)
		}
		n.Value = val
	case TagBinary:
		val, err := base64.StdEncoding.DecodeString(node.Value)
		if err != nil {
			return fmt.Errorf("failed to decode binary data: %w", err)
		}
		n.Value = val
	case TagMap:
		return n.handleMapTag(node)
	case TagSlice:
		return n.handleSliceTag(node)
	default:
		log.WithPrefix("k8s").Debug("Skipping unsupported node tag",
			log.String("tag", node.Tag),
			log.FilePath(n.Path),
			log.Int("line", node.Line),
		)
	}
	return nil
}

func (n *ManifestNode) handleSliceTag(node *yaml.Node) error {
	var nodes []*ManifestNode
	maxLine := node.Line
	for _, contentNode := range node.Content {
		newNode := new(ManifestNode)
		newNode.Path = n.Path
		if err := contentNode.Decode(newNode); err != nil {
			return err
		}
		if newNode.EndLine > maxLine {
			maxLine = newNode.EndLine
		}
		nodes = append(nodes, newNode)
	}
	n.EndLine = maxLine
	n.Value = nodes
	return nil
}

func (n *ManifestNode) handleMapTag(node *yaml.Node) error {
	output := make(map[string]*ManifestNode)
	var key string
	maxLine := node.Line
	for i, contentNode := range node.Content {
		if i == 0 || i%2 == 0 {
			key = contentNode.Value
		} else {
			newNode := new(ManifestNode)
			newNode.Path = n.Path
			if err := contentNode.Decode(newNode); err != nil {
				return err
			}
			output[key] = newNode
			if newNode.EndLine > maxLine {
				maxLine = newNode.EndLine
			}
		}
	}
	n.EndLine = maxLine
	n.Value = output
	return nil
}

func (n *ManifestNode) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var valPtr any
	var nodeType TagType
	switch k := dec.PeekKind(); k {
	case 't', 'f':
		valPtr = new(bool)
		nodeType = TagBool
	case '"':
		nodeType = TagStr
		valPtr = new(string)
	case '0':
		nodeType = TagInt
		valPtr = new(uint64)
	case '[':
		valPtr = new([]*ManifestNode)
		nodeType = TagSlice
	case '{':
		valPtr = new(map[string]*ManifestNode)
		nodeType = TagMap
	case 'n':
		// TODO: UnmarshalJSONFrom is called only for the root null
		return dec.SkipValue()
	case 0:
		return dec.SkipValue()
	default:
		return fmt.Errorf("unexpected token kind %q at %d", k.String(), dec.InputOffset())
	}

	if err := json.UnmarshalDecode(dec, valPtr); err != nil {
		return err
	}

	n.Value = reflect.ValueOf(valPtr).Elem().Interface()
	n.Type = nodeType
	return nil
}

func (n *ManifestNode) Walk(f func(n *ManifestNode)) {
	f(n)
	switch n.Type {
	case TagSlice:
		for _, node := range n.Value.([]*ManifestNode) {
			node.Walk(f)
		}
	case TagMap:
		for _, node := range n.Value.(map[string]*ManifestNode) {
			node.Walk(f)
		}
	}
}
