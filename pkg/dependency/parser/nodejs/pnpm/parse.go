package pnpm

import (
	"fmt"
	"golang.org/x/exp/maps"
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

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
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

		pkgs = append(pkgs, ftypes.Package{
			ID:           pkgID,
			Name:         name,
			Version:      version,
			Relationship: lo.Ternary(isDirectPkg(name, lockFile.Dependencies), ftypes.RelationshipDirect, ftypes.RelationshipIndirect),
		})

		if len(dependencies) > 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: dependencies,
			})
		}
	}

	return pkgs, deps
}

func (p *Parser) parseV9(lockFile LockFile) ([]ftypes.Package, []ftypes.Dependency) {
	resolvedPkgs := make(map[string]ftypes.Package)
	resolvedDeps := make(map[string]ftypes.Dependency)

	directDeps := make(map[string]any)
	for n, d := range lo.Assign(lockFile.Importers.Root.DevDependencies, lockFile.Importers.Root.Dependencies) {
		directDeps[packageID(n, d.Version)] = struct{}{}
	}

	// Check all snapshots and save with resolved versions
	resolvedSnapshots := make(map[string][]string)
	for depPath, snapshot := range lockFile.Snapshots {
		name, version := p.parseDepPath(depPath, v6VersionSep)

		var dependsOn []string
		for depName, depVer := range lo.Assign(snapshot.OptionalDependencies, snapshot.Dependencies) {
			resolvedDepName, resolvedDepVer := p.parseDepPath(packageID(depName, depVer), v6VersionSep)
			id := packageID(resolvedDepName, resolvedDepVer)
			if _, ok := lockFile.Packages[id]; ok {
				dependsOn = append(dependsOn, id)
			}
		}
		if dependsOn != nil {
			sort.Strings(dependsOn)
			resolvedSnapshots[packageID(name, version)] = dependsOn
		}

	}

	for depPath, pkgInfo := range lockFile.Packages {
		name, version, _ := strings.Cut(depPath, v6VersionSep)

		// Remove versions for local packages/archives
		if strings.HasPrefix(version, "file:") {
			version = ""
		}

		if pkgInfo.Version != "" {
			version = pkgInfo.Version
		}

		// Save pkg
		id := packageID(name, version)
		resolvedPkgs[id] = ftypes.Package{
			ID:           id,
			Name:         name,
			Version:      version,
			Relationship: lo.Ternary(isDirectPkg(id, directDeps), ftypes.RelationshipDirect, ftypes.RelationshipIndirect),
			Dev:          true, // Mark all libs as Dev. We will update this later.
		}

		//Check child deps
		if dependsOn, ok := resolvedSnapshots[id]; ok {
			resolvedDeps[id] = ftypes.Dependency{
				ID:        id,
				DependsOn: dependsOn,
			}
		}
	}

	// Overwrite the Dev field for root and their child dependencies.
	for n, d := range lockFile.Importers.Root.Dependencies {
		p.markRootPkgs(packageID(n, d.Version), resolvedPkgs, resolvedDeps)
	}

	return maps.Values(resolvedPkgs), maps.Values(resolvedDeps)
}

// markRootPkgs sets `Dev` to false for non dev dependency.
func (p *Parser) markRootPkgs(id string, libs map[string]ftypes.Package, deps map[string]ftypes.Dependency) {
	lib, ok := libs[id]
	if !ok {
		return
	}

	lib.Dev = false
	libs[id] = lib

	// Update child deps
	for _, depID := range deps[id].DependsOn {
		p.markRootPkgs(depID, libs, deps)
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
		return name, ""
	}
	return name, version
}

func isDirectPkg(name string, directDeps map[string]interface{}) bool {
	_, ok := directDeps[name]
	return ok
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Pnpm, name, version)
}
