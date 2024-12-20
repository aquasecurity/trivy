package npm

import (
	"fmt"
	"io"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/liamg/jfather"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const nodeModulesDir = "node_modules"

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
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Resolved             string            `json:"resolved"`
	Dev                  bool              `json:"dev"`
	Link                 bool              `json:"link"`
	Workspaces           []string          `json:"workspaces"`
	StartLine            int
	EndLine              int
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("npm"),
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile LockFile
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}
	if err := jfather.Unmarshal(input, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	var pkgs []ftypes.Package
	var deps []ftypes.Dependency
	if lockFile.LockfileVersion == 1 {
		pkgs, deps = p.parseV1(lockFile.Dependencies, make(map[string]string))
	} else {
		pkgs, deps = p.parseV2(lockFile.Packages)
	}

	return utils.UniquePackages(pkgs), uniqueDeps(deps), nil
}

func (p *Parser) parseV2(packages map[string]Package) ([]ftypes.Package, []ftypes.Dependency) {
	pkgs := make(map[string]ftypes.Package, len(packages)-1)
	var deps []ftypes.Dependency

	// Resolve links first
	// https://docs.npmjs.com/cli/v9/configuring-npm/package-lock-json#packages
	p.resolveLinks(packages)

	directDeps := set.New[string]()
	for name, version := range lo.Assign(packages[""].Dependencies, packages[""].OptionalDependencies, packages[""].DevDependencies, packages[""].PeerDependencies) {
		pkgPath := joinPaths(nodeModulesDir, name)
		if _, ok := packages[pkgPath]; !ok {
			p.logger.Debug("Unable to find the direct dependency",
				log.String("name", name), log.String("version", version))
			continue
		}
		// Store the package paths of direct dependencies
		// e.g. node_modules/body-parser
		directDeps.Append(pkgPath)
	}

	for pkgPath, pkg := range packages {
		if !strings.HasPrefix(pkgPath, "node_modules") {
			continue
		}

		// pkg.Name exists when package name != folder name
		pkgName := pkg.Name
		if pkgName == "" {
			pkgName = p.pkgNameFromPath(pkgPath)
		}

		pkgID := packageID(pkgName, pkg.Version)
		location := ftypes.Location{
			StartLine: pkg.StartLine,
			EndLine:   pkg.EndLine,
		}

		var ref ftypes.ExternalRef
		if pkg.Resolved != "" {
			ref = ftypes.ExternalRef{
				Type: ftypes.RefOther,
				URL:  pkg.Resolved,
			}
		}

		pkgIndirect := isIndirectPkg(pkgPath, directDeps)

		// There are cases when similar packages use same dependencies
		// we need to add location for each these dependencies
		if savedPkg, ok := pkgs[pkgID]; ok {
			savedPkg.Dev = savedPkg.Dev && pkg.Dev
			if savedPkg.Relationship == ftypes.RelationshipIndirect && !pkgIndirect {
				savedPkg.Relationship = ftypes.RelationshipDirect
			}

			if ref.URL != "" && !slices.Contains(savedPkg.ExternalReferences, ref) {
				savedPkg.ExternalReferences = append(savedPkg.ExternalReferences, ref)
				sortExternalReferences(savedPkg.ExternalReferences)
			}

			savedPkg.Locations = append(savedPkg.Locations, location)
			sort.Sort(savedPkg.Locations)

			pkgs[pkgID] = savedPkg
			continue
		}

		newPkg := ftypes.Package{
			ID:                 pkgID,
			Name:               pkgName,
			Version:            pkg.Version,
			Relationship:       lo.Ternary(pkgIndirect, ftypes.RelationshipIndirect, ftypes.RelationshipDirect),
			Dev:                pkg.Dev,
			ExternalReferences: lo.Ternary(ref.URL != "", []ftypes.ExternalRef{ref}, nil),
			Locations:          []ftypes.Location{location},
		}
		pkgs[pkgID] = newPkg

		// npm builds graph using optional deps. e.g.:
		// └─┬ watchpack@1.7.5
		// ├─┬ chokidar@3.5.3 - optional dependency
		// │ └── glob-parent@5.1.
		dependencies := lo.Assign(pkg.Dependencies, pkg.OptionalDependencies, pkg.PeerDependencies)
		dependsOn := make([]string, 0, len(dependencies))
		for depName, depVersion := range dependencies {
			depID, err := findDependsOn(pkgPath, depName, packages)
			if err != nil {
				p.logger.Debug("Unable to resolve the version",
					log.String("name", depName), log.String("version", depVersion))
				continue
			}
			dependsOn = append(dependsOn, depID)
		}

		if len(dependsOn) > 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        newPkg.ID,
				DependsOn: dependsOn,
			})
		}

	}

	return lo.Values(pkgs), deps
}

// for local package npm uses links. e.g.:
// function/func1 -> target of package
// node_modules/func1 -> link to target
// see `package-lock_v3_with_workspace.json` to better understanding
func (p *Parser) resolveLinks(packages map[string]Package) {
	links := lo.PickBy(packages, func(pkgPath string, pkg Package) bool {
		if !pkg.Link {
			return false
		}
		if pkg.Resolved == "" {
			p.logger.Warn("`package-lock.json` contains broken link with empty `resolved` field. This package will be skipped to avoid receiving an empty package", log.String("pkg", pkgPath))
			delete(packages, pkgPath)
			return false
		}
		return true
	})
	// Early return
	if len(links) == 0 {
		return
	}

	rootPkg := packages[""]
	if rootPkg.Dependencies == nil {
		rootPkg.Dependencies = make(map[string]string)
	}

	workspaces := rootPkg.Workspaces
	// Changing the map during the map iteration causes unexpected behavior,
	// so we need to iterate over the cloned `packages` map, but change the original `packages` map.
	for pkgPath, pkg := range maps.Clone(packages) {
		for linkPath, link := range links {
			if !strings.HasPrefix(pkgPath, link.Resolved) {
				continue
			}
			// The target doesn't have the "resolved" field, so we need to copy it from the link.
			if pkg.Resolved == "" {
				pkg.Resolved = link.Resolved
			}

			// Resolve the link package so all packages are located under "node_modules".
			resolvedPath := strings.ReplaceAll(pkgPath, link.Resolved, linkPath)
			packages[resolvedPath] = pkg

			// Delete the target package
			delete(packages, pkgPath)

			if p.isWorkspace(pkgPath, workspaces) {
				rootPkg.Dependencies[p.pkgNameFromPath(linkPath)] = pkg.Version
			}
			break
		}
	}
	packages[""] = rootPkg
}

func (p *Parser) isWorkspace(pkgPath string, workspaces []string) bool {
	for _, workspace := range workspaces {
		if match, err := path.Match(workspace, pkgPath); err != nil {
			p.logger.Debug("Unable to parse workspace",
				log.String("workspace", workspace), log.String("pkg_path", pkgPath))
		} else if match {
			return true
		}
	}
	return false
}

func findDependsOn(pkgPath, depName string, packages map[string]Package) (string, error) {
	depPath := joinPaths(pkgPath, nodeModulesDir)
	paths := strings.Split(depPath, "/")
	// Try to resolve the version with the nearest directory
	// e.g. for pkgPath == `node_modules/body-parser/node_modules/debug`, depName == `ms`:
	//    - "node_modules/body-parser/node_modules/debug/node_modules/ms"
	//    - "node_modules/body-parser/node_modules/ms"
	//    - "node_modules/ms"
	for i := len(paths) - 1; i >= 0; i-- {
		if paths[i] != nodeModulesDir {
			continue
		}
		modulePath := joinPaths(paths[:i+1]...)
		modulePath = joinPaths(modulePath, depName)

		if dep, ok := packages[modulePath]; ok {
			return packageID(depName, dep.Version), nil
		}
	}

	// It should not reach here.
	return "", xerrors.Errorf("can't find dependsOn for %s", depName)
}

func (p *Parser) parseV1(dependencies map[string]Dependency, versions map[string]string) ([]ftypes.Package, []ftypes.Dependency) {
	// Update package name and version mapping.
	for pkgName, dep := range dependencies {
		// Overwrite the existing package version so that the nested version can take precedence.
		versions[pkgName] = dep.Version
	}

	var pkgs []ftypes.Package
	var deps []ftypes.Dependency
	for pkgName, dep := range dependencies {
		pkg := ftypes.Package{
			ID:           packageID(pkgName, dep.Version),
			Name:         pkgName,
			Version:      dep.Version,
			Dev:          dep.Dev,
			Relationship: ftypes.RelationshipUnknown, // lockfile v1 schema doesn't have information about direct dependencies
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  dep.Resolved,
				},
			},
			Locations: []ftypes.Location{
				{
					StartLine: dep.StartLine,
					EndLine:   dep.EndLine,
				},
			},
		}
		pkgs = append(pkgs, pkg)

		dependsOn := make([]string, 0, len(dep.Requires))
		for pName, requiredVer := range dep.Requires {
			// Try to resolve the version with nested dependencies first
			if resolvedDep, ok := dep.Dependencies[pName]; ok {
				pkgID := packageID(pName, resolvedDep.Version)
				dependsOn = append(dependsOn, pkgID)
				continue
			}

			// Try to resolve the version with the higher level dependencies
			if ver, ok := versions[pName]; ok {
				dependsOn = append(dependsOn, packageID(pName, ver))
				continue
			}

			// It should not reach here.
			p.logger.Warn("Unable to resolve the version",
				log.String("name", pName), log.String("version", requiredVer))
		}

		if len(dependsOn) > 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        packageID(pkg.Name, pkg.Version),
				DependsOn: dependsOn,
			})
		}

		if dep.Dependencies != nil {
			// Recursion
			childpkgs, childDeps := p.parseV1(dep.Dependencies, maps.Clone(versions))
			pkgs = append(pkgs, childpkgs...)
			deps = append(deps, childDeps...)
		}
	}

	return pkgs, deps
}

func (p *Parser) pkgNameFromPath(pkgPath string) string {
	// lock file contains path to dependency in `node_modules`. e.g.:
	// node_modules/string-width
	// node_modules/string-width/node_modules/strip-ansi
	// we renamed to `node_modules` directory prefixes `workspace` when resolving Links
	// node_modules/function1
	// node_modules/nested_func/node_modules/debug
	if index := strings.LastIndex(pkgPath, nodeModulesDir); index != -1 {
		return pkgPath[index+len(nodeModulesDir)+1:]
	}
	p.logger.Warn("Package path doesn't have `node_modules` prefix", log.String("pkg_path", pkgPath))
	return pkgPath
}

func uniqueDeps(deps []ftypes.Dependency) []ftypes.Dependency {
	var uniqDeps ftypes.Dependencies
	unique := set.New[string]()

	for _, dep := range deps {
		sort.Strings(dep.DependsOn)
		depKey := fmt.Sprintf("%s:%s", dep.ID, strings.Join(dep.DependsOn, ","))
		if !unique.Contains(depKey) {
			unique.Append(depKey)
			uniqDeps = append(uniqDeps, dep)
		}
	}

	sort.Sort(uniqDeps)
	return uniqDeps
}

func isIndirectPkg(pkgPath string, directDeps set.Set[string]) bool {
	// A project can contain 2 different versions of the same dependency.
	// e.g. `node_modules/string-width/node_modules/strip-ansi` and `node_modules/string-ansi`
	// direct dependencies always have root path (`node_modules/<pkg_name>`)
	if directDeps.Contains(pkgPath) {
		return false
	}
	return true
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

func packageID(name, version string) string {
	return dependency.ID(ftypes.Npm, name, version)
}

func sortExternalReferences(refs []ftypes.ExternalRef) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Type != refs[j].Type {
			return refs[i].Type < refs[j].Type
		}
		return refs[i].URL < refs[j].URL
	})
}
