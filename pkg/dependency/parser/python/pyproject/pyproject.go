package pyproject

import (
	"fmt"
	"io"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/poetry"
)

type PyProject struct {
	Tool Tool `toml:"tool"`
}

type Tool struct {
	Poetry Poetry `toml:"poetry"`
}

type PackageName string

func (a *PackageName) UnmarshalText(text []byte) error {
	var err error
	*a = PackageName(poetry.NormalizePkgName(string(text)))
	return err
}

type Poetry struct {
	Dependencies dependencies     `toml:"dependencies"`
	Groups       map[string]Group `toml:"group"`
}

type Group struct {
	Dependencies dependencies `toml:"dependencies"`
}

type dependencies map[string]any

func (d *dependencies) UnmarshalTOML(data any) error {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("dependencies must be map, but got: %T", data)
	}

	*d = lo.MapKeys(m, func(_ any, pkgName string) string {
		return poetry.NormalizePkgName(pkgName)
	})
	return nil
}

// Parser parses pyproject.toml defined in PEP518.
// https://peps.python.org/pep-0518/
type Parser struct {
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r io.Reader) (PyProject, error) {
	var conf PyProject
	if _, err := toml.NewDecoder(r).Decode(&conf); err != nil {
		return PyProject{}, xerrors.Errorf("toml decode error: %w", err)
	}
	return conf, nil
}
