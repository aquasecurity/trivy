package yaml

import (
	"bytes"

	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"
)

// Parser is a YAML parser.
type Parser struct{}

// Parse parses YAML files.
func (p *Parser) Parse(b []byte) (interface{}, error) {
	var v interface{}
	if err := yaml.Unmarshal(b, &v); err != nil {
		return nil, xerrors.Errorf("unmarshal yaml: %w", err)
	}

	return v, nil
}

// SeparateSubDocuments separates YAML file
func (p *Parser) SeparateSubDocuments(data []byte) [][]byte {
	linebreak := "\n"
	if bytes.Contains(data, []byte("\r\n---\r\n")) {
		linebreak = "\r\n"
	}

	return bytes.Split(data, []byte(linebreak+"---"+linebreak))
}
