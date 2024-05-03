package pnpm

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const (
	v5VersionSep = "/"
	v6VersionSep = "@"
)

type PackageResolution struct {
	Tarball string `yaml:"tarball,omitempty"`
}

type PackageInfo struct {
	Resolution      PackageResolution `yaml:"resolution"`
	Dependencies    map[string]string `yaml:"dependencies,omitempty"`
	DevDependencies map[string]string `yaml:"devDependencies,omitempty"`
	IsDev           bool              `yaml:"dev,omitempty"`
	Name            string            `yaml:"name,omitempty"`
	Version         string            `yaml:"version,omitempty"`
}

type LockFile struct {
	LockfileVersion any                    `yaml:"lockfileVersion"`
	Dependencies    map[string]any         `yaml:"dependencies,omitempty"`
	DevDependencies map[string]any         `yaml:"devDependencies,omitempty"`
	Packages        map[string]PackageInfo `yaml:"packages,omitempty"`

	// V9
	Importers Importer            `yaml:"importers,omitempty"`
	Snapshots map[string]Snapshot `yaml:"snapshots,omitempty"`
}

type Importer struct {
	Root RootImporter `yaml:".,omitempty"`
}

type RootImporter struct {
	Dependencies    map[string]ImporterDepVersion `yaml:"dependencies,omitempty"`
	DevDependencies map[string]ImporterDepVersion `yaml:"devDependencies,omitempty"`
}

type ImporterDepVersion struct {
	Version string `yaml:"version,omitempty"`
}

type Snapshot struct {
	Dependencies         map[string]string `yaml:"dependencies,omitempty"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies,omitempty"`
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("pnpm"),
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile LockFile
	if err := yaml.NewDecoder(r).Decode(&lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	lockVer := p.parseLockfileVersion(lockFile)
	if lockVer < 0 {
		return nil, nil, nil
	}

	var libs []types.Library
	var deps []types.Dependency
	if lockVer >= 9 {
		libs, deps = p.parseV9(lockFile)
	} else {
		libs, deps = p.parse(lockVer, lockFile)
	}

	sort.Sort(types.Libraries(libs))
	sort.Sort(types.Dependencies(deps))
	return libs, deps, nil
}

func (p *Parser) parse(lockVer float64, lockFile LockFile) ([]types.Library, []types.Dependency) {
	var libs []types.Library
	var deps []types.Dependency

	// Dependency path is a path to a dependency with a specific set of resolved subdependencies.
	// cf. https://github.com/pnpm/spec/blob/ad27a225f81d9215becadfa540ef05fa4ad6dd60/dependency-path.md
	for depPath, info := range lockFile.Packages {
		if info.IsDev {
			continue
		}

		// Dependency name may be present in dependencyPath or Name field. Same for Version.
		// e.g. packages installed from local directory or tarball
		// cf. https://github.com/pnpm/spec/blob/274ff02de23376ad59773a9f25ecfedd03a41f64/lockfile/6.0.md#packagesdependencypathname
		name := info.Name
		version := info.Version

		if name == "" {
			name, version = p.parsePackage(depPath, lockVer)
		}
		pkgID := packageID(name, version)

		dependencies := make([]string, 0, len(info.Dependencies))
		for depName, depVer := range info.Dependencies {
			dependencies = append(dependencies, packageID(depName, depVer))
		}

		libs = append(libs, types.Library{
			ID:           pkgID,
			Name:         name,
			Version:      version,
			Relationship: lo.Ternary(isDirectLib(name, lockFile.Dependencies), types.RelationshipDirect, types.RelationshipIndirect),
		})

		if len(dependencies) > 0 {
			deps = append(deps, types.Dependency{
				ID:        pkgID,
				DependsOn: dependencies,
			})
		}
	}

	return libs, deps
}

func (p *Parser) parseV9(lockFile LockFile) ([]types.Library, []types.Dependency) {
	resolvedLibs := make(map[string]types.Library)
	resolvedDeps := make(map[string][]string)

	directDeps := make(map[string]any)
	for n, d := range lo.Assign(lockFile.Importers.Root.DevDependencies, lockFile.Importers.Root.Dependencies) {
		name, version := p.parseDepPath(packageID(n, d.Version), v6VersionSep)
		directDeps[packageID(name, version)] = struct{}{}
	}

	// Check all snapshots to get a list of resolved libraries and dependencies.
	for depPath, snapshot := range lockFile.Snapshots {
		// snapshots use unresolved strings
		// e.g. `debug@4.3.4(supports-color@8.1.1):`
		resolvedSnapshotName, resolvedSnapshotVersion := p.parseDepPath(depPath, v6VersionSep)

		id := packageID(resolvedSnapshotName, resolvedSnapshotVersion)
		resolvedLibs[id] = types.Library{
			ID:           id,
			Name:         resolvedSnapshotName,
			Version:      resolvedSnapshotVersion,
			Relationship: lo.Ternary(isDirectLib(id, directDeps), types.RelationshipDirect, types.RelationshipIndirect),
			Dev:          true, // Mark all libs as Dev. We will update this later.
		}

		var dependsOn []string
		for name, ver := range lo.Assign(snapshot.OptionalDependencies, snapshot.Dependencies) {
			// Dependency can be unresolved
			// e.g. dependencies:
			//        debug: 4.3.4(supports-color@8.1.1)
			snapshotID := packageID(name, ver)
			resolvedDepName, resolvedDepVersion := p.parseDepPath(snapshotID, v6VersionSep)
			// Don't include dependencies if `snapshots` don't contain them.
			// e.g. `snapshots` contain optional deps.
			// But peer deps are also marked as optional, but `snapshots` don't contain them.
			if _, ok := lockFile.Snapshots[snapshotID]; ok {
				dependsOn = append(dependsOn, packageID(resolvedDepName, resolvedDepVersion))
			}
		}
		if dependsOn != nil {
			sort.Strings(dependsOn)
			resolvedDeps[id] = dependsOn
		}
	}

	// Overwrite the Dev field for root and their child dependencies.
	for n, d := range lockFile.Importers.Root.Dependencies {
		p.markRootLibs(packageID(n, d.Version), resolvedLibs, resolvedDeps)
	}

	deps := lo.MapToSlice(resolvedDeps, func(id string, dependsOn []string) types.Dependency {
		return types.Dependency{
			ID:        id,
			DependsOn: dependsOn,
		}
	})

	libs := maps.Values(resolvedLibs)
	return libs, deps
}

// markRootLibs sets `Dev` to false for non dev dependency.
func (p *Parser) markRootLibs(id string, libs map[string]types.Library, deps map[string][]string) {
	lib, ok := libs[id]
	if !ok {
		return
	}

	lib.Dev = false
	libs[id] = lib

	// Update child deps
	for _, depID := range deps[id] {
		p.markRootLibs(depID, libs, deps)
	}
	return
}

func (p *Parser) parseLockfileVersion(lockFile LockFile) float64 {
	switch v := lockFile.LockfileVersion.(type) {
	// v5
	case float64:
		return v
	// v6+
	case string:
		if lockVer, err := strconv.ParseFloat(v, 64); err != nil {
			p.logger.Debug("Unable to convert the lock file version to float", log.Err(err))
			return -1
		} else {
			return lockVer
		}
	default:
		p.logger.Debug("Unknown type for the lock file version",
			log.Any("version", lockFile.LockfileVersion))
		return -1
	}
}

// parsePackage parses a `package` from a v6 or earlier lock file.
// cf. https://github.com/pnpm/pnpm/blob/ce61f8d3c29eee46cee38d56ced45aea8a439a53/packages/dependency-path/src/index.ts#L112-L163
func (p *Parser) parsePackage(depPath string, lockFileVersion float64) (string, string) {
	// The version separator is different between v5 and v6+.
	versionSep := v6VersionSep
	if lockFileVersion < 6 {
		versionSep = v5VersionSep
	}

	// Skip registry
	// e.g.
	//    - "registry.npmjs.org/lodash/4.17.10" => "lodash/4.17.10"
	//    - "registry.npmjs.org/@babel/generator/7.21.9" => "@babel/generator/7.21.9"
	//    - "/lodash/4.17.10" => "lodash/4.17.10"
	// 	  - "/asap@2.0.6" => "asap@2.0.6"
	_, depPath, _ = strings.Cut(depPath, "/")

	return p.parseDepPath(depPath, versionSep)
}

func (p *Parser) parseDepPath(depPath, versionSep string) (string, string) {
	// Parse scope
	// e.g.
	//    - v5:  "@babel/generator/7.21.9" => {"babel", "generator/7.21.9"}
	//    - v6+: "@babel/helper-annotate-as-pure@7.18.6" => "{"babel", "helper-annotate-as-pure@7.18.6"}
	var scope string
	if strings.HasPrefix(depPath, "@") {
		scope, depPath, _ = strings.Cut(depPath, "/")
	}

	// Parse package name
	// e.g.
	//    - v5:  "generator/7.21.9" => {"generator", "7.21.9"}
	//    - v6+: "helper-annotate-as-pure@7.18.6" => {"helper-annotate-as-pure", "7.18.6"}
	var name, version string
	name, version, _ = strings.Cut(depPath, versionSep)
	if scope != "" {
		name = fmt.Sprintf("%s/%s", scope, name)
	}
	// Trim peer deps
	// e.g.
	//    - v5:  "7.21.5_@babel+core@7.21.8" => "7.21.5"
	//    - v6+: "7.21.5(@babel/core@7.20.7)" => "7.21.5"
	if idx := strings.IndexAny(version, "_("); idx != -1 {
		version = version[:idx]
	}
	if _, err := semver.Parse(version); err != nil {
		p.logger.Debug("Skip non-semver package", log.String("pkg_path", depPath),
			log.String("version", version), log.Err(err))
		return "", ""
	}
	return name, version
}

func isDirectLib(name string, directDeps map[string]interface{}) bool {
	_, ok := directDeps[name]
	return ok
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Pnpm, name, version)
}
