package core_deps

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

// runtimePackPrefix is the name prefix the .NET SDK gives the bundled runtime in a
// self-contained app's deps.json, e.g. "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64".
const runtimePackPrefix = "runtimepack."

type dotNetDependencies struct {
	Libraries     map[string]dotNetLibrary        `json:"libraries"`
	RuntimeTarget RuntimeTarget                   `json:"runtimeTarget"`
	Targets       map[string]map[string]TargetLib `json:"targets"`
}

type dotNetLibrary struct {
	Type string `json:"type"`
	xjson.Location
}

type RuntimeTarget struct {
	Name string `json:"name"`
}

type TargetLib struct {
	Dependencies   map[string]string `json:"dependencies"`
	Runtime        any               `json:"runtime"`
	RuntimeTargets any               `json:"runtimeTargets"`
	Native         any               `json:"native"`
}

type Parser struct {
	logger *log.Logger
	once   sync.Once
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("dotnet"),
		once:   sync.Once{},
	}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var depsFile dotNetDependencies
	if err := xjson.UnmarshalRead(r, &depsFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode .deps.json file: %w", err)
	}

	// Get target libraries for RuntimeTarget
	targetLibs, targetLibsFound := depsFile.Targets[depsFile.RuntimeTarget.Name]
	if !targetLibsFound {
		// If the target is not found, take all dependencies
		p.logger.Debug("Unable to find `Target` for Runtime Target Name. All dependencies from `libraries` section will be included in the report", log.String("Runtime Target Name", depsFile.RuntimeTarget.Name))
	}

	// Normalize `targets` keys to the prefix-stripped ID space used by `pkgs` so runtime packs resolve in the graph pass below.
	targetLibs = lo.MapKeys(targetLibs, func(_ TargetLib, key string) string {
		name, version, _ := strings.Cut(key, "/")
		return packageID(name, version)
	})

	// First pass: collect all packages
	pkgs, rootPkgID := p.collectPackages(depsFile, targetLibs, targetLibsFound)
	if len(pkgs) == 0 {
		return nil, nil, nil
	}

	// If target libraries are not found, return all collected packages without dependencies
	if !targetLibsFound {
		pkgSlice := lo.Values(pkgs)
		sort.Sort(ftypes.Packages(pkgSlice))
		return pkgSlice, nil, nil
	}

	directDeps := lo.MapToSlice(targetLibs[rootPkgID].Dependencies, packageID)

	// Second pass: build dependency graph + fill Relationships from targets section
	deps := p.buildDependencyGraph(pkgs, targetLibs, directDeps)

	pkgSlice := lo.Values(pkgs)
	sort.Sort(ftypes.Packages(pkgSlice))
	sort.Sort(deps)
	return pkgSlice, deps, nil
}

// collectPackages builds the package map from the `libraries` section. It returns
// the packages keyed by ID and the ID of the root project ("" if it couldn't be
// determined). When a root is found, the root project is marked `RelationshipRoot`
// and the other project libraries `RelationshipWorkspace`.
func (p *Parser) collectPackages(depsFile dotNetDependencies, targetLibs map[string]TargetLib, targetLibsFound bool) (map[string]ftypes.Package, string) {
	pkgs := make(map[string]ftypes.Package, len(depsFile.Libraries))
	var projects []string

	for nameVer, lib := range depsFile.Libraries {
		name, version, ok := strings.Cut(nameVer, "/")
		if !ok {
			// Invalid name
			p.logger.Warn("Cannot parse .NET library version", log.String("library", nameVer))
			continue
		}

		// Skip unsupported library types.
		// `runtimepack` carries the bundled .NET runtime in self-contained deployments.
		if !strings.EqualFold(lib.Type, "package") && !strings.EqualFold(lib.Type, "project") && !strings.EqualFold(lib.Type, "runtimepack") {
			continue
		}

		// Strip the synthetic `runtimepack.` prefix so the runtime is reported under the same name as framework-dependent apps (e.g. Microsoft.NETCore.App.Runtime.linux-x64).
		name = strings.TrimPrefix(name, runtimePackPrefix)
		id := packageID(name, version)

		// Skip non-runtime libraries if target libraries are available.
		// `targetLibs` is keyed by the same stripped ID as `id`.
		if targetLibsFound && !p.isRuntimeLibrary(targetLibs, id) {
			// Skip non-runtime libraries
			// cf. https://github.com/aquasecurity/trivy/pull/7039#discussion_r1674566823
			continue
		}

		pkg := ftypes.Package{
			ID:        id,
			Name:      name,
			Version:   version,
			Locations: []ftypes.Location{ftypes.Location(lib.Location)},
		}

		if strings.EqualFold(lib.Type, "project") {
			projects = append(projects, id)
		}

		pkgs[pkg.ID] = pkg
	}

	rootPkgID := p.rootProject(projects, targetLibs)
	if rootPkgID != "" {
		for _, project := range projects {
			pkg := pkgs[project]
			pkg.Relationship = lo.Ternary(project == rootPkgID, ftypes.RelationshipRoot, ftypes.RelationshipWorkspace)
			pkgs[project] = pkg
		}
	}

	return pkgs, rootPkgID
}

// rootProject returns the pkgID of the root application project:
// the only `type: project` that no other library depends on in the `targets` graph.
// It returns "" when there isn't exactly one such project, so we don't guess the root on a non-standard file.
func (p *Parser) rootProject(projects []string, targetLibs map[string]TargetLib) string {
	referenced := set.New[string]()
	for _, lib := range targetLibs {
		for name, version := range lib.Dependencies {
			referenced.Append(packageID(name, version))
		}
	}

	var roots []string
	for _, project := range projects {
		if !referenced.Contains(project) {
			roots = append(roots, project)
		}
	}
	if len(roots) == 1 {
		return roots[0]
	}

	p.logger.Debug("Unable to determine the root project in .deps.json", log.Int("candidates", len(roots)))
	return ""
}

// buildDependencyGraph fills the Relationship field of each package and builds the
// dependency graph from the `targets` section.
func (p *Parser) buildDependencyGraph(pkgs map[string]ftypes.Package, targetLibs map[string]TargetLib, directDeps []string) ftypes.Dependencies {
	var deps ftypes.Dependencies
	for pkgID, pkg := range pkgs {
		// Fill relationship field for package
		// If Root package wasn't found or doesn't have dependencies, skip setting Relationship,
		// because most likely file is broken.
		// Root and workspace package relationships are already set.
		if len(directDeps) > 0 && pkg.Relationship == ftypes.RelationshipUnknown {
			pkg.Relationship = lo.Ternary(slices.Contains(directDeps, pkgID), ftypes.RelationshipDirect, ftypes.RelationshipIndirect)
			pkgs[pkgID] = pkg
		}

		// Build dependency graph
		dependencies, ok := targetLibs[pkgID]
		// Package doesn't have dependencies
		if !ok {
			continue
		}

		var dependsOn []string
		for depName, depVersion := range dependencies.Dependencies {
			depID := packageID(depName, depVersion)
			// Only create dependencies for packages that exist in package lists
			if _, exists := pkgs[depID]; exists {
				dependsOn = append(dependsOn, depID)
			}
		}
		if len(dependsOn) > 0 {
			sort.Strings(dependsOn)
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: dependsOn,
			})
		}
	}

	return deps
}

// isRuntimeLibrary returns true if library contains `runtime`, `runtimeTarget` or `native` sections, or if the library is missing from `targetLibs`.
// See https://github.com/aquasecurity/trivy/discussions/4282#discussioncomment-8830365 for more details.
func (p *Parser) isRuntimeLibrary(targetLibs map[string]TargetLib, library string) bool {
	lib, ok := targetLibs[library]
	// Selected target doesn't contain library
	// Mark these libraries as runtime to avoid mistaken omission
	if !ok {
		p.once.Do(func() {
			p.logger.Debug("Unable to determine that this is runtime library. Library not found in `Target` section.", log.String("Library", library))
		})
		return true
	}
	// Check that `runtime`, `runtimeTarget` and `native` sections are not empty
	return !lo.IsEmpty(lib.Runtime) || !lo.IsEmpty(lib.RuntimeTargets) || !lo.IsEmpty(lib.Native)
}

// packageID builds a package ID from a `.deps.json` name. It strips the synthetic
// `runtimepack.` prefix the .NET SDK adds to the bundled runtime in self-contained
// deployments so that runtime packs and the `targets` dependency references that point
// at them resolve to the same ID (e.g. Microsoft.NETCore.App.Runtime.linux-x64).
func packageID(name, version string) string {
	return dependency.ID(ftypes.DotNetCore, strings.TrimPrefix(name, runtimePackPrefix), version)
}
