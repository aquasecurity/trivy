package environment

import (
	"sort"
	"strings"
	"sync"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/go-version/pkg/version"
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
	once   sync.Once
}

func NewParser() types.Parser {
	return &Parser{
		logger: log.WithPrefix("conda"),
		once:   sync.Once{},
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var env environment
	if err := yaml.NewDecoder(r).Decode(&env); err != nil {
		return nil, nil, xerrors.Errorf("unable to decode conda environment.yml file: %w", err)
	}

	var libs []types.Library
	for _, dep := range env.Dependencies {
		lib := p.toLibrary(dep)
		// Skip empty libs
		if lib.Name == "" {
			continue
		}
		libs = append(libs, lib)
	}

	sort.Sort(types.Libraries(libs))
	return libs, nil, nil
}

func (p *Parser) toLibrary(dep Dependency) types.Library {
	name, ver := p.parseDependency(dep.Value)
	if ver == "" {
		p.once.Do(func() {
			p.logger.Warn("Unable to detect the dependency versions from `environment.yml` as those versions are not pinned. Use `conda env export` to pin versions.")
		})
	}
	return types.Library{
		Name:    name,
		Version: ver,
		Locations: types.Locations{
			{
				StartLine: dep.Line,
				EndLine:   dep.Line,
			},
		},
	}
}

// parseDependency parses the dependency line and returns the name and the pinned version.
// The version range is not supported. It parses only the pinned version.
// e.g.
//   - numpy 1.8.1
//   - numpy ==1.8.1
//   - numpy 1.8.1 py27_0
//   - numpy=1.8.1=py27_0
//
// cf. https://docs.conda.io/projects/conda-build/en/latest/resources/package-spec.html#examples-of-package-specs
func (*Parser) parseDependency(line string) (string, string) {
	line = strings.NewReplacer(">", " >", "<", " <", "=", " ").Replace(line)
	parts := strings.Fields(line)
	name := parts[0]
	if len(parts) == 1 {
		return name, ""
	}
	if _, err := version.Parse(parts[1]); err != nil {
		return name, ""
	}
	return name, parts[1]
}

func (d *Dependency) UnmarshalYAML(node *yaml.Node) error {
	d.Value = node.Value
	d.Line = node.Line
	return nil
}
