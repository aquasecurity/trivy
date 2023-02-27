package pyproject

import (
	"github.com/BurntSushi/toml"
	"golang.org/x/xerrors"
	"io"
)

type PyProject struct {
	Tool Tool `toml:"tool"`
}

type Tool struct {
	Poetry Poetry `toml:"poetry"`
}

type Poetry struct {
	Dependencies map[string]string `toml:"dependencies"`
}

// Parser parses pyproject.toml defined in PEP518.
// https://peps.python.org/pep-0518/
type Parser struct {
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r io.Reader) (map[string]string, error) {
	var conf PyProject
	if _, err := toml.NewDecoder(r).Decode(&conf); err != nil {
		return nil, xerrors.Errorf("toml decode error: %w", err)
	}
	return conf.Tool.Poetry.Dependencies, nil
}
