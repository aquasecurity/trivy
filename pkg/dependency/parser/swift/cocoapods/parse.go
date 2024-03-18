package cocoapods

import (
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

type lockFile struct {
	Pods []any `yaml:"PODS"` // pod can be string or map[string]interface{}
}

func (Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	lock := &lockFile{}
	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&lock); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode cocoapods lock file: %s", err.Error())
	}

	parsedDeps := make(map[string]types.Library) // dependency name => Library
	directDeps := make(map[string][]string)      // dependency name => slice of child dependency names
	for _, pod := range lock.Pods {
		switch p := pod.(type) {
		case string: // dependency with version number
			lib, err := parseDep(p)
			if err != nil {
				log.Logger.Debug(err)
				continue
			}
			parsedDeps[lib.Name] = lib
		case map[string]interface{}: // dependency with its child dependencies
			for dep, childDeps := range p {
				lib, err := parseDep(dep)
				if err != nil {
					log.Logger.Debug(err)
					continue
				}
				parsedDeps[lib.Name] = lib

				children, ok := childDeps.([]interface{})
				if !ok {
					return nil, nil, xerrors.Errorf("invalid value of cocoapods direct dependency: %q", childDeps)
				}

				for _, childDep := range children {
					s, ok := childDep.(string)
					if !ok {
						return nil, nil, xerrors.Errorf("must be string: %q", childDep)
					}
					directDeps[lib.Name] = append(directDeps[lib.Name], strings.Fields(s)[0])
				}
			}
		}
	}

	var deps []types.Dependency
	for dep, childDeps := range directDeps {
		var dependsOn []string
		// find versions for child dependencies
		for _, childDep := range childDeps {
			dependsOn = append(dependsOn, packageID(childDep, parsedDeps[childDep].Version))
		}
		deps = append(deps, types.Dependency{
			ID:        parsedDeps[dep].ID,
			DependsOn: dependsOn,
		})
	}

	sort.Sort(types.Dependencies(deps))
	return utils.UniqueLibraries(maps.Values(parsedDeps)), deps, nil
}

func parseDep(dep string) (types.Library, error) {
	// dep example:
	// 'AppCenter (4.2.0)'
	// direct dep examples:
	// 'AppCenter/Core'
	// 'AppCenter/Analytics (= 4.2.0)'
	// 'AppCenter/Analytics (-> 4.2.0)'
	ss := strings.Split(dep, " (")
	if len(ss) != 2 {
		return types.Library{}, xerrors.Errorf("Unable to determine cocoapods dependency: %q", dep)
	}

	name := ss[0]
	version := strings.Trim(strings.TrimSpace(ss[1]), "()")
	lib := types.Library{
		ID:      packageID(name, version),
		Name:    name,
		Version: version,
	}

	return lib, nil
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Cocoapods, name, version)
}
