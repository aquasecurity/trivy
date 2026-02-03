package parser

import (
	"io/fs"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
)

const (
	NullTag = "!!null"
	StrTag  = "!!str"
)

func decodeYAMLFileWithExtension(fileSrc fsutils.FileSource, dst any, extensions []string) error {
	for _, ext := range extensions {
		f := fsutils.FileSource{FS: fileSrc.FS, Path: fileSrc.Path + ext}
		if exists, _ := f.Exists(); exists {
			return decodeYAMLFile(f, dst)
		}
	}
	return fs.ErrNotExist
}

func decodeYAMLFile(f fsutils.FileSource, dst any) error {
	data, err := f.ReadFile()
	if err != nil {
		return xerrors.Errorf("read file %s: %w", f.Path, err)
	}

	if err := decodeYAML(data, dst); err != nil {
		return xerrors.Errorf("decode %s: %w", f.Path, err)
	}
	return nil
}

func decodeYAML(data []byte, dst any) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	unwrapTemplates(&root)
	return root.Decode(dst)
}

// unwrapTemplates recursively traverses a YAML node tree and converts
// any double-mapping nodes that represent templates (like {{ key }})
// into scalar nodes with the template string.
//
// Specifically, it detects nodes of the form:
//
//	MappingNode
//	  Content[0]: MappingNode
//	    Content[0]: ScalarNode (key)
//	    Content[1]: ScalarNode null
//	  Content[1]: ScalarNode null
//
// and converts them into:
//
//	ScalarNode "{{ key }}"
func unwrapTemplates(n *yaml.Node) {
	walk(n, func(node *yaml.Node) bool {
		if node.Kind != yaml.MappingNode || len(node.Content) != 2 {
			return false
		}

		innerKey := node.Content[0]
		innerVal := node.Content[1]

		if innerKey.Kind == yaml.MappingNode &&
			len(innerKey.Content) == 2 &&
			innerVal.Tag == NullTag &&
			innerKey.Content[0].Kind == yaml.ScalarNode &&
			innerKey.Content[0].Tag == StrTag &&
			innerKey.Content[1].Tag == NullTag {

			node.Kind = yaml.ScalarNode
			node.Tag = StrTag
			node.Value = "{{ " + innerKey.Content[0].Value + " }}"
			node.Content = nil
			return true
		}

		return false
	})
}

// walk traverses a YAML node tree and calls fn on each node.
// If fn returns true, walk stops traversing that branch.
func walk(n *yaml.Node, fn func(*yaml.Node) (stop bool)) bool {
	if fn(n) {
		return true
	}
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			walk(c, fn)
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			walk(n.Content[i], fn)
			walk(n.Content[i+1], fn)
		}
	case yaml.ScalarNode:
	}
	return false
}
