package cocoapods

import (
	"fmt"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

const idFormat = "%s/%s"

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

type lockFile struct {
	Pods []interface{} `yaml:"PODS"` // pod can be string or map[string]interface{}
}

func (Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	lock := &lockFile{}
	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&lock); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode cocoapods lock file: %s", err.Error())
	}

	parsedDeps := map[string]types.Library{} // dependency name => Library
	directDeps := map[string][]string{}      // dependency name => slice of child dependency names
	for _, pod := range lock.Pods {
		switch p := pod.(type) {
		case string: // dependency with version number
			lib, err := parseDep(pod.(string))
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
			dependsOn = append(dependsOn, pkgID(childDep, parsedDeps[childDep].Version))
		}
		deps = append(deps, types.Dependency{
			ID:        parsedDeps[dep].ID,
			DependsOn: dependsOn,
		})
	}

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
		ID:      pkgID(name, version),
		Name:    name,
		Version: version,
	}

	return lib, nil
}

func pkgID(name, version string) string {
	return fmt.Sprintf(idFormat, name, version)
}
