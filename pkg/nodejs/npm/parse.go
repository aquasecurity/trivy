package npm

import (
	"fmt"
	"github.com/samber/lo"
	"io"
	"sort"
	"strings"

	"github.com/liamg/jfather"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

const nodeModulesFolder = "node_modules"

type LockFile struct {
	Dependencies    map[string]Dependency `json:"dependencies"`
	Packages        map[string]Package    `json:"packages"`
	LockfileVersion int                   `json:"lockfileVersion"`
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
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Resolved             string            `json:"resolved"`
	Dev                  bool              `json:"dev"`
	StartLine            int
	EndLine              int
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

	var libs []types.Library
	var deps []types.Dependency
	if lockFile.LockfileVersion == 1 {
		libs, deps = p.parseV1(lockFile.Dependencies, map[string]string{})
	} else {
		libs, deps = p.parseV2(lockFile.Packages)
	}

	return utils.UniqueLibraries(libs), uniqueDeps(deps), nil
}

func (p *Parser) parseV2(packages map[string]Package) ([]types.Library, []types.Dependency) {
	libs := make(map[string]types.Library, len(packages)-1)
	var deps []types.Dependency

	directDeps := map[string]struct{}{}
	for name, version := range lo.Assign(packages[""].Dependencies, packages[""].OptionalDependencies) {
		pkgPath := joinPaths(nodeModulesFolder, name)
		if _, ok := packages[pkgPath]; !ok {
			log.Logger.Debugf("Unable to find the direct dependency: '%s@%s'", name, version)
			continue
		}
		// Store the package paths of direct dependencies
		// e.g. node_modules/body-parser
		directDeps[pkgPath] = struct{}{}
	}

	for pkgPath, pkg := range packages {
		if pkg.Dev || pkgPath == "" {
			continue
		}

		pkgName := pkgNameFromPath(pkgPath)
		pkgID := utils.PackageID(pkgName, pkg.Version)

		// There are cases when similar libraries use same dependencies
		// we need to add location for each these dependencies
		if savedLib, ok := libs[pkgID]; ok {
			savedLib.Locations = append(savedLib.Locations, types.Location{StartLine: pkg.StartLine, EndLine: pkg.EndLine})
			libs[pkgID] = savedLib
			continue
		}

		lib := types.Library{
			ID:                 pkgID,
			Name:               pkgName,
			Version:            pkg.Version,
			Indirect:           isIndirectLib(pkgPath, directDeps),
			ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: pkg.Resolved}},
			Locations: []types.Location{
				{
					StartLine: pkg.StartLine,
					EndLine:   pkg.EndLine,
				},
			},
		}
		libs[pkgID] = lib

		// npm builds graph using optional deps. e.g.:
		// └─┬ watchpack@1.7.5
		// ├─┬ chokidar@3.5.3 - optional dependency
		// │ └── glob-parent@5.1.
		dependencies := lo.Assign(pkg.Dependencies, pkg.OptionalDependencies)
		dependsOn := make([]string, 0, len(dependencies))
		for depName, depVersion := range dependencies {
			depID, err := findDependsOn(pkgPath, depName, packages)
			if err != nil {
				log.Logger.Warnf("Cannot resolve the version: '%s@%s'", depName, depVersion)
				continue
			}
			dependsOn = append(dependsOn, depID)
		}

		if len(dependsOn) > 0 {
			dep := types.Dependency{
				ID:        lib.ID,
				DependsOn: dependsOn,
			}
			deps = append(deps, dep)
		}

	}
	return maps.Values(libs), deps
}

func findDependsOn(pkgPath, depName string, packages map[string]Package) (string, error) {
	depPath := joinPaths(pkgPath, nodeModulesFolder)
	paths := strings.Split(depPath, "/")
	// Try to resolve the version with the nearest directory
	// e.g. for pkgPath == `node_modules/body-parser/node_modules/debug`, depName == `ms`:
	//    - "node_modules/body-parser/node_modules/debug/node_modules/ms"
	//    - "node_modules/body-parser/node_modules/ms"
	//    - "node_modules/ms"
	for i := len(paths) - 1; i >= 0; i-- {
		if paths[i] != nodeModulesFolder {
			continue
		}
		path := joinPaths(paths[:i+1]...)
		path = joinPaths(path, depName)

		if dep, ok := packages[path]; ok {
			return utils.PackageID(depName, dep.Version), nil
		}
	}
	// It should not reach here.
	return "", xerrors.Errorf("can't find dependsOn for %s", depName)
}

func (p *Parser) parseV1(dependencies map[string]Dependency, versions map[string]string) ([]types.Library, []types.Dependency) {
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
			Indirect:           true, // lockfile v1 schema doesn't have information about Direct dependencies
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
			childLibs, childDeps := p.parseV1(dependency.Dependencies, maps.Clone(versions))
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

func isIndirectLib(pkgPath string, directDeps map[string]struct{}) bool {
	// A project can contain 2 different versions of the same dependency.
	// e.g. `node_modules/string-width/node_modules/strip-ansi` and `node_modules/string-ansi`
	// direct dependencies always have root path (`node_modules/<lib_name>`)
	_, ok := directDeps[pkgPath]
	return !ok
}

func pkgNameFromPath(path string) string {
	// lock file contains path to dependency in `node_modules` folder. e.g.:
	// node_modules/string-width
	// node_modules/string-width/node_modules/strip-ansi
	paths := strings.Split(path, "/")
	// deps starting from `@` have pgkName with one `/`
	// e.g. path == `node_modules/@babel/plugin-transform-classes` => pkgName == `@babel/plugin-transform-classes`
	if len(paths) >= 2 && strings.HasPrefix(paths[len(paths)-2], "@") {
		return strings.Join(paths[len(paths)-2:], "/")
	}
	return paths[len(paths)-1]
}

func joinPaths(paths ...string) string {
	return strings.Join(paths, "/")
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps for v1
func (t *Dependency) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps for v2 or newer
func (t *Package) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}
