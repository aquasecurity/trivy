package pnpm

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
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
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile LockFile
	if err := yaml.NewDecoder(r).Decode(&lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	lockVer := parseLockfileVersion(lockFile)
	if lockVer < 0 {
		return nil, nil, nil
	}

	libs, deps := p.parse(lockVer, lockFile)

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
			name, version = parsePackage(depPath, lockVer)
		}
		pkgID := packageID(name, version)

		dependencies := make([]string, 0, len(info.Dependencies))
		for depName, depVer := range info.Dependencies {
			dependencies = append(dependencies, packageID(depName, depVer))
		}

		libs = append(libs, types.Library{
			ID:       pkgID,
			Name:     name,
			Version:  version,
			Indirect: isIndirectLib(name, lockFile.Dependencies),
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

func parseLockfileVersion(lockFile LockFile) float64 {
	switch v := lockFile.LockfileVersion.(type) {
	// v5
	case float64:
		return v
	// v6+
	case string:
		if lockVer, err := strconv.ParseFloat(v, 64); err != nil {
			log.Logger.Debugf("Unable to convert the lock file version to float: %s", err)
			return -1
		} else {
			return lockVer
		}
	default:
		log.Logger.Debugf("Unknown type for the lock file version: %s", lockFile.LockfileVersion)
		return -1
	}
}

func isIndirectLib(name string, directDeps map[string]interface{}) bool {
	_, ok := directDeps[name]
	return !ok
}

// cf. https://github.com/pnpm/pnpm/blob/ce61f8d3c29eee46cee38d56ced45aea8a439a53/packages/dependency-path/src/index.ts#L112-L163
func parsePackage(depPath string, lockFileVersion float64) (string, string) {
	// The version separator is different between v5 and v6+.
	versionSep := "@"
	if lockFileVersion < 6 {
		versionSep = "/"
	}
	return parseDepPath(depPath, versionSep)
}

func parseDepPath(depPath, versionSep string) (string, string) {
	// Skip registry
	// e.g.
	//    - "registry.npmjs.org/lodash/4.17.10" => "lodash/4.17.10"
	//    - "registry.npmjs.org/@babel/generator/7.21.9" => "@babel/generator/7.21.9"
	//    - "/lodash/4.17.10" => "lodash/4.17.10"
	_, depPath, _ = strings.Cut(depPath, "/")

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
		log.Logger.Debugf("Skip %q package. %q doesn't match semver: %s", depPath, version, err)
		return "", ""
	}
	return name, version
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Pnpm, name, version)
}
