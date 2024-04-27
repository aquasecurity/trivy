package environment

import (
	"regexp"
	"sort"
	"strings"
	"sync"

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
	once   sync.Once
}

func NewParser() types.Parser {
	return &Parser{
		logger: log.WithPrefix("conda"),
		once:   sync.Once{},
	}
}

var manuallyCreatedPkgRegexp = regexp.MustCompile(`(?P<name>[A-Za-z0-9-_]+)( |>|<|=|!|$)`)

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
	lib := types.Library{
		Locations: types.Locations{
			{
				StartLine: dep.Line,
				EndLine:   dep.Line,
			},
		},
	}

	// `Conda env export` command returns `<pkg_name>=<version><build>` format.
	ss := strings.Split(dep.Value, "=")
	// But `environment.yml` supports version range (for manually created files).
	// cf. https://docs.conda.io/projects/conda-build/en/latest/resources/package-spec.html#examples-of-package-specs
	if len(ss) != 3 || strings.ContainsAny(dep.Value, "<>!*") || strings.Contains(dep.Value, "==") {
		p.once.Do(func() {
			p.logger.Warn("Unable to detect the versions of dependencies from `environment.yml` as they are not pinned. Use `conda env export` to pin versions.")
		})

		// Detect only name for manually created dependencies.
		var name string
		matches := manuallyCreatedPkgRegexp.FindStringSubmatch(dep.Value)
		if matches != nil {
			name = matches[manuallyCreatedPkgRegexp.SubexpIndex("name")]
		}
		if name == "" {
			p.logger.Debug("Unable to parse dependency", log.String("dep", dep.Value))
			return types.Library{}
		}

		lib.Name = name
		return lib
	}

	lib.Name = ss[0]
	lib.Version = ss[1]
	return lib
}

func (d *Dependency) UnmarshalYAML(node *yaml.Node) error {
	d.Value = node.Value
	d.Line = node.Line
	return nil
}
