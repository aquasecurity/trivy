package parser

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"gopkg.in/yaml.v3"
)

type Manifest struct {
	Path    string
	Content *ManifestNode
}

func (m *Manifest) UnmarshalYAML(value *yaml.Node) error {

	switch value.Tag {
	case string(TagMap):
		node := new(ManifestNode)
		node.Path = m.Path
		if err := value.Decode(node); err != nil {
			return err
		}
		m.Content = node
	default:
		return fmt.Errorf("failed to handle tag: %s", value.Tag)
	}

	return nil
}

func (m *Manifest) ToRego() any {
	return m.Content.ToRego()
}

func ManifestFromJSON(path string, data []byte) (*Manifest, error) {
	root := &ManifestNode{
		Path: path,
	}

	if err := json.Unmarshal(data, root, json.WithUnmarshalers(
		json.UnmarshalFromFunc(func(dec *jsontext.Decoder, node *ManifestNode, opts json.Options) error {
			startOffset := dec.InputOffset()
			if err := unmarshalManifestNode(dec, node); err != nil {
				return err
			}
			endOffset := dec.InputOffset()
			node.StartLine = 1 + countLines(data, int(startOffset))
			node.EndLine = 1 + countLines(data, int(endOffset))
			node.Path = path
			return nil
		})),
	); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	return &Manifest{
		Path:    path,
		Content: root,
	}, nil
}

func unmarshalManifestNode(dec *jsontext.Decoder, node *ManifestNode) error {
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
	case '[', 'n':
		valPtr = new([]*ManifestNode)
		nodeType = TagSlice
	case '{':
		valPtr = new(map[string]*ManifestNode)
		nodeType = TagMap
	case 0:
		return dec.SkipValue()
	default:
		return fmt.Errorf("unexpected token kind %q at %d", k.String(), dec.InputOffset())
	}

	if err := json.UnmarshalDecode(dec, valPtr); err != nil {
		return err
	}

	node.Value = reflect.ValueOf(valPtr).Elem().Interface()
	node.Type = nodeType
	return nil
}

func countLines(data []byte, offset int) int {
	return bytes.Count(data[:offset], []byte("\n"))
}
