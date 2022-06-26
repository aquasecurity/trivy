package pnpm

import (
	"fmt"
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

type PackageResolution struct {
	Integrity string `yaml:"integrity"`
}

type PackageInfo struct {
	Resolution           PackageResolution `yaml:"resolution"`
	Engines              map[string]string `yaml:"engines,omitempty"`
	Specifiers           map[string]string `yaml:"specifiers,omitempty"`
	Dependencies         map[string]string `yaml:"dependencies,omitempty"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies,omitempty"`
	DevDependencies      map[string]string `yaml:"devDependencies,omitempty"`
	IsDev                bool              `yaml:"dev,omitempty"`
	IsOptional           bool              `yaml:"optional,omitempty"`
}

type LockFile struct {
	LockfileVersion      int8                   `yaml:"lockfileVersion"`
	Importers            map[string]PackageInfo `yaml:"importers,omitempty"`
	Specifiers           map[string]string      `yaml:"specifiers,omitempty"`
	Dependencies         map[string]string      `yaml:"dependencies,omitempty"`
	OptionalDependencies map[string]string      `yaml:"optionalDependencies,omitempty"`
	DevDependencies      map[string]string      `yaml:"devDependencies,omitempty"`
	Packages             map[string]PackageInfo `yaml:"packages,omitempty"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) ID(name, version string) string {
	return fmt.Sprintf("%s@%s", name, version)
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile LockFile
	decoder := yaml.NewDecoder(r)
	err := decoder.Decode(&lockFile)
	if err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	libs, deps := p.parse(&lockFile)

	return libs, deps, nil
}

func (p *Parser) parse(lockFile *LockFile) ([]types.Library, []types.Dependency) {
	var libs []types.Library
	var deps []types.Dependency

	for pkg, info := range lockFile.Packages {
		if info.IsDev {
			continue
		}

		dependencies := make([]string, 0)
		name, version := getPackageNameAndVersion(pkg)
		id := p.ID(name, version)

		for depName, depVer := range info.Dependencies {
			dependencies = append(dependencies, p.ID(depName, depVer))
		}

		libs = append(libs, types.Library{
			ID:       id,
			Name:     name,
			Version:  version,
			Indirect: isIndirectLib(name, lockFile.Dependencies),
		})

		if len(dependencies) > 0 {
			deps = append(deps, types.Dependency{
				ID:        id,
				DependsOn: dependencies,
			})
		}
	}

	return libs, deps
}

func isIndirectLib(name string, directDeps map[string]string) bool {
	_, ok := directDeps[name]
	return !ok
}

func getPackageNameAndVersion(pkg string) (string, string) {
	idx := strings.LastIndex(pkg, "/")
	name := pkg[1:idx]
	version := pkg[idx+1:]

	return name, version
}
