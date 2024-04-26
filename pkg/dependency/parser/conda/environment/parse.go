package environment

import (
	"sort"
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
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
	// Default format for files created using the `conda Export` command: `<Name>=<Version>=<Build>
	// e.g. `bzip2=1.0.8=h998d150_5`
	// But it is also possible to set only the dependency name
	ss := strings.Split(dep.Value, "=")

	lib := types.Library{
		Name: ss[0],
		Locations: types.Locations{
			{
				StartLine: dep.Line,
				EndLine:   dep.Line,
			},
		},
	}

	// Version can be omitted
	if len(ss) == 1 {
		p.logger.Warn("Unable to detect the version as it is not pinned", log.String("name", dep.Value))
		return lib, nil
	}

	lib.Version = ss[1]
	return lib, nil
}

func (d *Dependency) UnmarshalYAML(node *yaml.Node) error {
	d.Value = node.Value
	d.Line = node.Line
	return nil
}
