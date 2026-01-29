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
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

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

	// First pass: collect all packages
	var projectNameVer string
	pkgs := make(map[string]ftypes.Package, len(depsFile.Libraries))

	for nameVer, lib := range depsFile.Libraries {
		name, version, ok := strings.Cut(nameVer, "/")
		if !ok {
			// Invalid name
			p.logger.Warn("Cannot parse .NET library version", log.String("library", nameVer))
			continue
		}

		// Skip unsupported library types
		if !strings.EqualFold(lib.Type, "package") && !strings.EqualFold(lib.Type, "project") {
			continue
		}

		// Skip non-runtime libraries if target libraries are available
		if targetLibsFound && !p.isRuntimeLibrary(targetLibs, nameVer) {
			// Skip non-runtime libraries
			// cf. https://github.com/aquasecurity/trivy/pull/7039#discussion_r1674566823
			continue
		}

		pkg := ftypes.Package{
			ID:        packageID(name, version),
			Name:      name,
			Version:   version,
			Locations: []ftypes.Location{ftypes.Location(lib.Location)},
		}

		// Identify root package
		if strings.EqualFold(lib.Type, "project") {
			if projectNameVer != "" {
				p.logger.Warn("Multiple root projects found in .deps.json", log.String("existing_root", projectNameVer), log.String("new_root", nameVer))
				continue
			}
			projectNameVer = nameVer
			pkg.Relationship = ftypes.RelationshipRoot
		}

		pkgs[pkg.ID] = pkg
	}

	if len(pkgs) == 0 {
		return nil, nil, nil
	}

	// If target libraries are not found, return all collected packages without dependencies
	if !targetLibsFound {
		pkgSlice := lo.Values(pkgs)
		sort.Sort(ftypes.Packages(pkgSlice))
		return pkgSlice, nil, nil
	}

	directDeps := lo.MapToSlice(targetLibs[projectNameVer].Dependencies, packageID)

	// Second pass: build dependency graph + fill Relationships from targets section
	var deps ftypes.Dependencies
	for pkgID, pkg := range pkgs {
		// Fill relationship field for package
		// If Root package didn't find or don't have dependencies, skip setting Relationship,
		// because most likely file is broken.
		// Root package Relationship is already set
		if len(directDeps) > 0 && pkg.Relationship != ftypes.RelationshipRoot {
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
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: dependsOn,
			})
		}
	}

	pkgSlice := lo.Values(pkgs)
	sort.Sort(ftypes.Packages(pkgSlice))
	sort.Sort(deps)
	return pkgSlice, deps, nil
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

func packageID(name, version string) string {
	return dependency.ID(ftypes.DotNetCore, name, version)
}
