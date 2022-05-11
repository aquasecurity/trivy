package types

import dio "github.com/aquasecurity/go-dep-parser/pkg/io"

type Library struct {
	ID       string `json:",omitempty"`
	Name     string
	Version  string
	Indirect bool   `json:",omitempty"`
	License  string `json:",omitempty"`
}

type Dependency struct {
	ID        string
	DependsOn []string
}

type Parser interface {
	// Parse parses the dependency file
	Parse(r dio.ReadSeekerAt) ([]Library, []Dependency, error)
}
