package environment

import (
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
	"sort"
	"strings"
)

type environment struct {
	Dependencies []Dependency `yaml:"dependencies"`
}

type Dependency struct {
	Value string
	Line  int
}

type Parser struct {
	logger *log.Logger
}

func NewParser() types.Parser {
	return &Parser{
		logger: log.WithPrefix("conda"),
	}
}

// TODO add comment
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var env environment
	if err := yaml.NewDecoder(r).Decode(&env); err != nil {
		return nil, nil, xerrors.Errorf("unable to decode conda environment.yml file: %w", err)
	}

	var libs []types.Library
	for _, dep := range env.Dependencies {
		lib, err := p.toLibrary(dep)
		if err != nil {
			return nil, nil, xerrors.Errorf("unable to parse dependency: %w", err)
		}
		libs = append(libs, lib)
	}

	sort.Sort(types.Libraries(libs))
	return libs, nil, nil
}

func (p *Parser) toLibrary(dep Dependency) (types.Library, error) {
	ss := strings.Split(dep.Value, "=")
	if len(ss) == 1 {
		p.logger.Debug("Unable to detect version", log.String("dependency", dep.Value))
	}
	return types.Library{}, nil
}

func (d *Dependency) UnmarshalYAML(node *yaml.Node) error {
	d.Value = node.Value
	d.Line = node.Line
	return nil
}
