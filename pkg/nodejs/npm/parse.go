package npm

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/liamg/jfather"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

type LockFile struct {
	Dependencies map[string]Dependency `json:"dependencies"`
	Packages     map[string]Package    `json:"packages"`
}
type Dependency struct {
	Version      string                `json:"version"`
	Dev          bool                  `json:"dev"`
	Dependencies map[string]Dependency `json:"dependencies"`
	Requires     map[string]string     `json:"requires"`
	Resolved     string                `json:"resolved"`
	StartLine    int
	EndLine      int
}

type Package struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile LockFile
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}
	if err := jfather.Unmarshal(input, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	dircetDeps := lockFile.Packages[""].Dependencies
	libs, deps := p.parse(lockFile.Dependencies, dircetDeps, map[string]string{})

	return utils.UniqueLibraries(libs), uniqueDeps(deps), nil
}

func (p *Parser) parse(dependencies map[string]Dependency, dircetDeps map[string]string, versions map[string]string) ([]types.Library, []types.Dependency) {
	// Update package name and version mapping.
	for pkgName, dep := range dependencies {
		// Overwrite the existing package version so that the nested version can take precedence.
		versions[pkgName] = dep.Version
	}

	var libs []types.Library
	var deps []types.Dependency
	for pkgName, dependency := range dependencies {
		if dependency.Dev {
			continue
		}

		lib := types.Library{
			ID:                 utils.PackageID(pkgName, dependency.Version),
			Name:               pkgName,
			Version:            dependency.Version,
			Indirect:           isIndirectLib(pkgName, dircetDeps),
			ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: dependency.Resolved}},
			Locations: []types.Location{
				{
					StartLine: dependency.StartLine,
					EndLine:   dependency.EndLine,
				},
			},
		}
		libs = append(libs, lib)

		dependsOn := make([]string, 0, len(dependency.Requires))
		for libName, requiredVer := range dependency.Requires {
			// Try to resolve the version with nested dependencies first
			if resolvedDep, ok := dependency.Dependencies[libName]; ok {
				libID := utils.PackageID(libName, resolvedDep.Version)
				dependsOn = append(dependsOn, libID)
				continue
			}

			// Try to resolve the version with the higher level dependencies
			if ver, ok := versions[libName]; ok {
				dependsOn = append(dependsOn, utils.PackageID(libName, ver))
				continue
			}

			// It should not reach here.
			log.Logger.Warnf("Cannot resolve the version: %s@%s", libName, requiredVer)
		}

		if len(dependsOn) > 0 {
			deps = append(deps, types.Dependency{ID: utils.PackageID(lib.Name, lib.Version), DependsOn: dependsOn})
		}

		if dependency.Dependencies != nil {
			// Recursion
			childLibs, childDeps := p.parse(dependency.Dependencies, dircetDeps, maps.Clone(versions))
			libs = append(libs, childLibs...)
			deps = append(deps, childDeps...)
		}
	}

	return libs, deps
}

func uniqueDeps(deps []types.Dependency) []types.Dependency {
	var uniqDeps []types.Dependency
	unique := make(map[string]struct{})

	for _, dep := range deps {
		sort.Strings(dep.DependsOn)
		depKey := fmt.Sprintf("%s:%s", dep.ID, strings.Join(dep.DependsOn, ","))
		if _, ok := unique[depKey]; !ok {
			unique[depKey] = struct{}{}
			uniqDeps = append(uniqDeps, dep)
		}
	}
	return uniqDeps
}

func isIndirectLib(libName string, dircetDeps map[string]string) bool {
	_, ok := dircetDeps[libName]
	return !ok
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *Dependency) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}
