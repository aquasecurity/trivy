package pyproject

import (
	"io"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	"github.com/aquasecurity/trivy/pkg/set"
)

type PyProject struct {
	Tool Tool `toml:"tool"`
}

type Tool struct {
	Poetry Poetry `toml:"poetry"`
}

type Poetry struct {
	Dependencies Dependencies     `toml:"dependencies"`
	Groups       map[string]Group `toml:"group"`
}

type Group struct {
	Dependencies Dependencies `toml:"dependencies"`
}

type Dependencies struct {
	set.Set[string]
}

func (d *Dependencies) UnmarshalTOML(data any) error {
	m, ok := data.(map[string]any)
	if !ok {
		return xerrors.Errorf("dependencies must be map, but got: %T", data)
	}

	d.Set = set.New[string](lo.MapToSlice(m, func(pkgName string, _ any) string {
		return python.NormalizePkgName(pkgName)
	})...)
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
