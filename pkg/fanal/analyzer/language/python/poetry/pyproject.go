package poetry

import (
	"io"

	"github.com/BurntSushi/toml"
	"golang.org/x/xerrors"
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

// TODO: move under go-dep-parser
type PyProjectParser struct {
}

func (p *PyProjectParser) Parse(r io.Reader) (PyProject, error) {
	var conf PyProject
	if _, err := toml.NewDecoder(r).Decode(&conf); err != nil {
		return PyProject{}, xerrors.Errorf("toml decode error: %w", err)
	}
	return conf, nil
}
