package pnpm

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("pnpm"),
	}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile LockFile
	if err := yaml.NewDecoder(r).Decode(&lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	lockVer := p.parseLockfileVersion(lockFile)
	if lockVer < 0 {
		return nil, nil, nil
	}

	var pkgs []ftypes.Package
	var deps []ftypes.Dependency
	if lockVer >= 9 {
		pkgs, deps = p.parseV9(lockFile)
	} else {
		pkgs, deps = p.parse(lockVer, lockFile)
	}

	sort.Sort(ftypes.Packages(pkgs))
	sort.Sort(ftypes.Dependencies(deps))
	return pkgs, deps, nil
}

func (p *Parser) parse(lockVer float64, lockFile LockFile) ([]ftypes.Package, []ftypes.Dependency) {
	var pkgs []ftypes.Package
	var deps []ftypes.Dependency

	// Dependency path is a path to a dependency with a specific set of resolved subdependencies.
	// cf. https://github.com/pnpm/spec/blob/ad27a225f81d9215becadfa540ef05fa4ad6dd60/dependency-path.md
	for pkgKey, info := range lockFile.Packages {
		if info.IsDev {
			continue
		}

		// Dependency name may be present in dependencyPath or Name field. Same for Version.
		// e.g. packages installed from local directory or tarball
		// cf. https://github.com/pnpm/spec/blob/274ff02de23376ad59773a9f25ecfedd03a41f64/lockfile/6.0.md#packagesdependencypathname
		name := info.Name
		version := info.Version
		var ref string

		if name == "" {
			name, version, ref = p.parsePnpmKey(string(pkgKey), lockVer)
			version = p.parseVersion(string(pkgKey), version, lockVer)
		}
		// Create Trivy's internal package ID
		pkgID := packageID(name, version)

		dependencies := make([]string, 0, len(info.Dependencies))
		for depName, depVer := range info.Dependencies {
			dependencies = append(dependencies, packageID(depName, depVer))
		}

		pkgs = append(pkgs, ftypes.Package{
			ID:                 pkgID,
			Name:               name,
			Version:            version,
			Relationship:       lo.Ternary(isDirectPkg(name, lockFile.Dependencies), ftypes.RelationshipDirect, ftypes.RelationshipIndirect),
			ExternalReferences: toExternalRefs(ref),
		})

		if len(dependencies) > 0 {
			sort.Strings(dependencies)
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: dependencies,
			})
		}
	}

	return pkgs, deps
}

// parseV9 parses pnpm-lock.yaml version 9.x format and returns packages and their dependencies.
// Version 9 introduced "snapshots" where each snapshot represents a package with its exact resolved dependencies.
func (p *Parser) parseV9(lockFile LockFile) ([]ftypes.Package, []ftypes.Dependency) {
	lockVer := 9.0
	resolvedPkgs := make(map[SnapshotKey]ftypes.Package)
	resolvedDeps := make(map[SnapshotKey]ftypes.Dependency)

	// Step 1: Extract direct dependencies from the "importers" section.
	// The "importers" section contains the dependencies defined in package.json files.
	// We need to identify which packages are direct dependencies (vs transitive)
	// and which are development dependencies (vs production dependencies).
	devDeps := make(map[string]string) // name -> version for dev dependencies
	deps := make(map[string]string)    // name -> version for production dependencies
	for _, importer := range lockFile.Importers {
		for n, v := range importer.DevDependencies {
			devDeps[n] = v.Version
		}
		for n, v := range importer.Dependencies {
			deps[n] = v.Version
		}
	}

	// Step 2: Process each snapshot to create package entries.
	// Each snapshot represents a unique package installation with specific peer dependencies.
	// The snapshotKey is the key that uniquely identifies this package instance,
	// including any peer dependency information (e.g., "package@1.0.0(peer@2.0.0)").
	for snapshotKey, snapshot := range lockFile.Snapshots {
		name, version, ref := p.parsePnpmKey(string(snapshotKey), lockVer)
		// Clean and validate the version string (remove file: or http: prefixes if invalid)
		parsedVer := p.parseVersion(string(snapshotKey), version, lockVer)

		// Try to get the exact version from the "packages" section if available.
		// The "packages" section may contain more accurate version information
		// for packages installed from non-standard sources (git, local files, etc.).
		pkgKey := PackageKey(packageID(name, version))
		if pkgInfo, ok := lockFile.Packages[pkgKey]; ok && pkgInfo.Version != "" {
			parsedVer = pkgInfo.Version
		}

		// Step 3: Determine if this package is a direct or transitive dependency,
		// and whether it's a development or production dependency.
		// By default, assume it's a development dependency (will be corrected later if needed).
		dev := true
		relationship := ftypes.RelationshipIndirect // Assume transitive by default

		// Check if this package matches a direct dev dependency
		if v, ok := devDeps[name]; ok && p.trimPeerDeps(v, lockVer) == version {
			relationship = ftypes.RelationshipDirect
		}
		// Check if this package matches a direct production dependency
		if v, ok := deps[name]; ok && p.trimPeerDeps(v, lockVer) == version {
			relationship = ftypes.RelationshipDirect
			dev = false // This is a production dependency, not a dev dependency
		}

		// Create the package entry with all extracted information.
		pkg := ftypes.Package{
			// ID is the full snapshotKey which uniquely identifies this package instance
			// including any peer dependency context.
			ID:                 string(snapshotKey),
			Name:               name,
			Version:            parsedVer,
			Relationship:       relationship,
			Dev:                dev,
			ExternalReferences: toExternalRefs(ref),
		}
		resolvedPkgs[snapshotKey] = pkg

		// Step 4: Build the dependency graph by recording what this package depends on.
		var dependsOn []string // List of snapshot keys this package depends on
		for depName, depVer := range lo.Assign(snapshot.OptionalDependencies, snapshot.Dependencies) {
			normalizedDepVer := p.trimPeerDeps(depVer, lockVer)
			// Only include dependencies that are actually installed (exist in "packages" section).
			if _, ok := lockFile.Packages[PackageKey(packageID(depName, normalizedDepVer))]; ok {
				// Use the original name/version string (with peer deps) to build the snapshot key correctly.
				dependsOn = append(dependsOn, packageID(depName, depVer))
			}
		}
		if len(dependsOn) > 0 {
			resolvedDeps[snapshotKey] = ftypes.Dependency{
				ID:        string(snapshotKey),
				DependsOn: dependsOn,
			}
		}
	}

	// Step 5: Propagate the "production" status to all transitive dependencies.
	// If a package is a production dependency (Dev=false), all packages it depends on
	// should also be marked as production dependencies, even if they were initially
	// marked as dev dependencies. This ensures we correctly identify which packages
	// are needed for production vs only for development.
	visited := set.New[SnapshotKey]()
	for _, pkg := range resolvedPkgs {
		if !pkg.Dev { // If this is a production dependency
			// Recursively mark this package and all its dependencies as production
			p.markRootPkgs(SnapshotKey(pkg.ID), resolvedPkgs, resolvedDeps, visited)
		}
	}

	return lo.Values(resolvedPkgs), lo.Values(resolvedDeps)
}

// markRootPkgs recursively marks a package and all its dependencies as production dependencies.
// This is used to propagate the production status from direct production dependencies
// to all their transitive dependencies, ensuring that any package required for production
// is correctly identified, even if it's also listed as a dev dependency elsewhere.
func (p *Parser) markRootPkgs(id SnapshotKey, pkgs map[SnapshotKey]ftypes.Package, deps map[SnapshotKey]ftypes.Dependency, visited set.Set[SnapshotKey]) {
	// Avoid infinite recursion in case of circular dependencies
	if visited.Contains(id) {
		return
	}
	// Get the package; skip if not found
	pkg, ok := pkgs[id]
	if !ok {
		return
	}

	// Mark this package as a production dependency
	pkg.Dev = false
	pkgs[id] = pkg
	visited.Append(id) // Track that we've processed this package

	// Recursively process all dependencies of this package
	for _, depID := range deps[id].DependsOn {
		p.markRootPkgs(SnapshotKey(depID), pkgs, deps, visited)
	}
}

func (p *Parser) parseLockfileVersion(lockFile LockFile) float64 {
	switch v := lockFile.LockfileVersion.(type) {
	// v5
	case float64:
		return v
	// v6+
	case string:
		lockVer, err := strconv.ParseFloat(v, 64)
		if err != nil {
			p.logger.Debug("Unable to convert the lock file version to float", log.Err(err))
			return -1
		}
		return lockVer
	default:
		p.logger.Debug("Unknown type for the lock file version",
			log.Any("version", lockFile.LockfileVersion))
		return -1
	}
}

// parsePnpmKey parses a pnpm package key (either PackageKey or SnapshotKey)
// and extracts the package name, version, and optional registry reference.
// The key format varies between pnpm versions:
//   - v5:  "registry.npmjs.org/@babel/generator/7.21.9"
//   - v6+: "@babel/generator@7.21.9"
//   - v9+: "@babel/generator@7.21.9(peer@1.0.0)" (SnapshotKey with peers)
func (p *Parser) parsePnpmKey(pnpmKey string, lockVer float64) (string, string, string) {
	dPath, nonDefaultRegistry := p.trimRegistry(pnpmKey, lockVer)

	var scope string
	scope, dPath = p.separateScope(dPath)

	var name string
	name, dPath = p.separateName(dPath, lockVer)

	// add scope to pkg name
	if scope != "" {
		name = fmt.Sprintf("%s/%s", scope, name)
	}

	ver := p.trimPeerDeps(dPath, lockVer)

	return name, ver, lo.Ternary(nonDefaultRegistry, pnpmKey, "")
}

// trimRegistry trims registry (or `/` prefix) from a pnpm key.
// It returns true if non-default registry has been trimmed.
// e.g.
//   - "registry.npmjs.org/lodash/4.17.10" => "lodash/4.17.10", false
//   - "registry.npmjs.org/@babel/generator/7.21.9" => "@babel/generator/7.21.9", false
//   - "private.npm.org/@babel/generator/7.21.9" => "@babel/generator/7.21.9", true
//   - "/lodash/4.17.10" => "lodash/4.17.10", false
//   - "/asap@2.0.6" => "asap@2.0.6", false
func (p *Parser) trimRegistry(pnpmKey string, lockVer float64) (string, bool) {
	var nonDefaultRegistry bool
	// lock file v9 doesn't use registry prefix
	if lockVer < 9 {
		var registry string
		registry, pnpmKey, _ = strings.Cut(pnpmKey, "/")
		if registry != "" && registry != "registry.npmjs.org" {
			nonDefaultRegistry = true
		}
	}
	return pnpmKey, nonDefaultRegistry
}

// separateScope separates the scope (if set) from the rest of the pnpm key.
// e.g.
//   - v5:  "@babel/generator/7.21.9" => {"babel", "generator/7.21.9"}
//   - v6+: "@babel/helper-annotate-as-pure@7.18.6" => {"babel", "helper-annotate-as-pure@7.18.6"}
func (p *Parser) separateScope(pnpmKey string) (string, string) {
	var scope string
	if strings.HasPrefix(pnpmKey, "@") {
		scope, pnpmKey, _ = strings.Cut(pnpmKey, "/")
	}
	return scope, pnpmKey
}

// separateName separates package name and version from a pnpm key.
// e.g.
//   - v5:  "generator/7.21.9" => {"generator", "7.21.9"}
//   - v6+: "7.21.5(@babel/core@7.20.7)" => "7.21.5"
//
// for v9+ version can be filePath or link:
//   - "package1@file:package1:"
//   - "is-negative@https://codeload.github.com/zkochan/is-negative/tar.gz/2fa0531ab04e300a24ef4fd7fb3a280eccb7ccc5"
//
// Also version can contain peer deps:
//   - "debug@4.3.4(supports-color@8.1.1)"
func (p *Parser) separateName(pnpmKey string, lockVer float64) (string, string) {
	sep := "@"
	if lockVer < 6 {
		sep = "/"
	}
	name, version, _ := strings.Cut(pnpmKey, sep)
	return name, version
}

// trimPeerDeps removes peer dependency suffixes from a version string.
// e.g.
//   - v5:  "7.21.5_@babel+core@7.21.8" => "7.21.5"
//   - v6+: "7.21.5(@babel/core@7.20.7)" => "7.21.5"
func (p *Parser) trimPeerDeps(version string, lockVer float64) string {
	sep := "("
	if lockVer < 6 {
		sep = "_"
	}
	v, _, _ := strings.Cut(version, sep)
	return v
}

// parseVersion parses version.
// v9 can use filePath or link as version - we need to clear these versions.
// e.g.
//   - "package1@file:package1:"
//   - "is-negative@https://codeload.github.com/zkochan/is-negative/tar.gz/2fa0531ab04e300a24ef4fd7fb3a280eccb7ccc5"
//
// Other versions should be semver valid.
func (p *Parser) parseVersion(depPath, ver string, lockVer float64) string {
	if lockVer < 9 && (strings.HasPrefix(ver, "file:") || strings.HasPrefix(ver, "http")) {
		return ""
	}
	if _, err := semver.Parse(ver); err != nil {
		p.logger.Debug("Skip non-semver package", log.String("pkg_path", depPath),
			log.String("version", ver), log.Err(err))
		return ""
	}

	return ver
}

func isDirectPkg(name string, directDeps map[string]any) bool {
	_, ok := directDeps[name]
	return ok
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Pnpm, name, version)
}

func toExternalRefs(ref string) []ftypes.ExternalRef {
	if ref == "" {
		return nil
	}
	return []ftypes.ExternalRef{
		{
			Type: ftypes.RefVCS,
			URL:  ref,
		},
	}
}
