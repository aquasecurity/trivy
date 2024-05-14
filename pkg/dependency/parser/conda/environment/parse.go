package environment

import (
	"sort"
	"strings"
	"sync"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/go-version/pkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("conda"),
		once:   sync.Once{},
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var env environment
	if err := yaml.NewDecoder(r).Decode(&env); err != nil {
		return nil, nil, xerrors.Errorf("unable to decode conda environment.yml file: %w", err)
	}

	var pkgs ftypes.Packages
	for _, dep := range env.Dependencies {
		pkg := p.toPackage(dep)
		// Skip empty pkgs
		if pkg.Name == "" {
			continue
		}
		pkgs = append(pkgs, pkg)
	}

	sort.Sort(pkgs)
	return pkgs, nil, nil
}

func (p *Parser) toPackage(dep Dependency) ftypes.Package {
	name, ver := p.parseDependency(dep.Value)
	if ver == "" {
		p.once.Do(func() {
			p.logger.Warn("Unable to detect the dependency versions from `environment.yml` as those versions are not pinned. Use `conda env export` to pin versions.")
		})
	}
	return ftypes.Package{
		Name:    name,
		Version: ver,
		Locations: ftypes.Locations{
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
