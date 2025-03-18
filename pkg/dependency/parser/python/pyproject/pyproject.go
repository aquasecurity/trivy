package pyproject

import (
	"io"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	"github.com/aquasecurity/trivy/pkg/set"
)

type PyProject struct {
	Tool    Tool    `toml:"tool"`
	Project Project `toml:"project"`
}

type Project struct {
	Dependencies Dependencies `toml:"dependencies"`
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

// MainDeps returns set of main deps
// `poetry` only uses 1 list of main dependencies
// `project.dependencies` (first priority) or `tool.poetry.dependencies` (if `project.dependencies` is missing)
func (p PyProject) MainDeps() set.Set[string] {
	deps := set.New[string]()
	if p.Project.Dependencies.Set != nil {
		deps.Append(p.Project.Dependencies.Items()...)
	} else if p.Tool.Poetry.Dependencies.Set != nil {
		deps.Append(p.Tool.Poetry.Dependencies.Items()...)
	}
	return deps
}

func (d *Dependencies) UnmarshalTOML(data any) error {
	switch deps := data.(type) {
	case map[string]any: // For Poetry v1
		d.Set = set.New[string](lo.MapToSlice(deps, func(pkgName string, _ any) string {
			return python.NormalizePkgName(pkgName)
		})...)
	case []any: // For Poetry v2
		d.Set = set.New[string]()
		for i := range deps {
			dep, ok := deps[i].(string)
			if !ok {
				return xerrors.Errorf("dependencies must be string, but got: %T", deps[i])
			}
			// There are some formats:
			// e.g. `Flask == 1.1.4`, `Flask==1.1.4`, `Flask(>= 1.0.0)`, `pluggy[pre-commit,tox] (==0.13.1)`, etc.
			dep = strings.NewReplacer(">", " ", "<", " ", "=", " ", "(", " ", "[", " ").Replace(dep)
			d.Set.Append(strings.Fields(dep)[0]) // Save only name
		}
	default:
		return xerrors.Errorf("dependencies must be map, but got: %T", data)
	}

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
