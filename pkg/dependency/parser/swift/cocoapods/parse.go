package cocoapods

import (
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("cocoapods"),
	}
}

type lockFile struct {
	Pods []any `yaml:"PODS"` // pod can be string or map[string]interface{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	lock := &lockFile{}
	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&lock); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode cocoapods lock file: %s", err.Error())
	}

	parsedDeps := make(map[string]ftypes.Package) // dependency name => Package
	directDeps := make(map[string][]string)       // dependency name => slice of child dependency names
	for _, pod := range lock.Pods {
		switch dep := pod.(type) {
		case string: // dependency with version number
			pkg, err := parseDep(dep)
			if err != nil {
				p.logger.Debug("Dependency parse error", log.Err(err))
				continue
			}
			parsedDeps[pkg.Name] = pkg
		case map[string]any:
			for dep, childDeps := range dep {
				pkg, err := parseDep(dep)
				if err != nil {
					p.logger.Debug("Dependency parse error", log.Err(err))
					continue
				}
				parsedDeps[pkg.Name] = pkg

				children, ok := childDeps.([]any)
				if !ok {
					return nil, nil, xerrors.Errorf("invalid value of cocoapods direct dependency: %q", childDeps)
				}

				for _, childDep := range children {
					s, ok := childDep.(string)
					if !ok {
						return nil, nil, xerrors.Errorf("must be string: %q", childDep)
					}
					directDeps[pkg.Name] = append(directDeps[pkg.Name], strings.Fields(s)[0])
				}
			}
		}
	}

	var deps ftypes.Dependencies
	for dep, childDeps := range directDeps {
		var dependsOn []string
		// find versions for child dependencies
		for _, childDep := range childDeps {
			dependsOn = append(dependsOn, packageID(childDep, parsedDeps[childDep].Version))
		}
		deps = append(deps, ftypes.Dependency{
			ID:        parsedDeps[dep].ID,
			DependsOn: dependsOn,
		})
	}

	sort.Sort(deps)
	return utils.UniquePackages(lo.Values(parsedDeps)), deps, nil
}

func parseDep(dep string) (ftypes.Package, error) {
	// dep example:
	// 'AppCenter (4.2.0)'
	// direct dep examples:
	// 'AppCenter/Core'
	// 'AppCenter/Analytics (= 4.2.0)'
	// 'AppCenter/Analytics (-> 4.2.0)'
	ss := strings.Split(dep, " (")
	if len(ss) != 2 {
		return ftypes.Package{}, xerrors.Errorf("Unable to determine cocoapods dependency: %q", dep)
	}

	name := ss[0]
	version := strings.Trim(strings.TrimSpace(ss[1]), "()")
	pkg := ftypes.Package{
		ID:      packageID(name, version),
		Name:    name,
		Version: version,
	}

	return pkg, nil
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Cocoapods, name, version)
}
