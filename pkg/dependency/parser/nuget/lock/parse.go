package lock

import (
	"context"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type LockFile struct {
	Version int                     `json:"version"`
	Targets map[string]Dependencies `json:"dependencies"`
}

type Dependencies map[string]Dependency

type Dependency struct {
	Type         string            `json:"type"`
	Resolved     string            `json:"resolved"`
	Dependencies map[string]string `json:"dependencies,omitempty"`
	xjson.Location
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile LockFile
	if err := xjson.UnmarshalRead(r, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode packages.lock.json: %w", err)
	}

	var pkgs []ftypes.Package
	depsMap := make(map[string][]string)
	for _, targetContent := range lockFile.Targets {
		for packageName, packageContent := range targetContent {
			// If package type is "project", it is the actual project, and we skip it.
			if packageContent.Type == "Project" {
				continue
			}

			depId := packageID(packageName, packageContent.Resolved)

			pkg := ftypes.Package{
				ID:           depId,
				Name:         packageName,
				Version:      packageContent.Resolved,
				Relationship: lo.Ternary(packageContent.Type == "Direct", ftypes.RelationshipDirect, ftypes.RelationshipIndirect),
				Locations:    []ftypes.Location{ftypes.Location(packageContent.Location)},
			}
			pkgs = append(pkgs, pkg)

			var dependsOn []string

			for depName := range packageContent.Dependencies {
				dependsOn = append(dependsOn, packageID(depName, targetContent[depName].Resolved))
			}

			if savedDependsOn, ok := depsMap[depId]; ok {
				dependsOn = lo.Uniq(append(dependsOn, savedDependsOn...))
			}

			if len(dependsOn) > 0 {
				depsMap[depId] = dependsOn
			}
		}
	}

	var deps []ftypes.Dependency
	for depId, dependsOn := range depsMap {
		dep := ftypes.Dependency{
			ID:        depId,
			DependsOn: dependsOn,
		}
		deps = append(deps, dep)
	}

	return utils.UniquePackages(pkgs), deps, nil
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.NuGet, name, version)
}
