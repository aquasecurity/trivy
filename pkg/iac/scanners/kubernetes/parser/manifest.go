package parser

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/ast"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type Manifest struct {
	Path   string
	Offset int
	Root   *ast.Node
}

func (m *Manifest) Validate() error {
	if m.Root == nil {
		return errors.New("content is nil")
	}

	if m.Root.Kind != ast.MappingNode {
		return fmt.Errorf("expected root node to be a map, got %s", m.Root.Kind)
	}

	return nil
}

func (m *Manifest) IsEmpty() bool {
	if m.Root == nil {
		return true
	}
	v, ok := m.Root.Value.(map[string]*ast.Node)
	if !ok {
		return true
	}
	return len(v) == 0
}

func (m *Manifest) ToRego() any {
	return NodeToRego(m.Root, m.Path, m.Offset)
}

func ManifestFromYAML(path string, data []byte, offset int) (*Manifest, error) {
	var root ast.Node

	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	return &Manifest{
		Path:   path,
		Root:   &root,
		Offset: offset,
	}, nil
}

func ManifestFromJSON(path string, data []byte) (*Manifest, error) {
	var root ast.Node

	if err := xjson.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	return &Manifest{
		Path: path,
		Root: &root,
	}, nil
}
