package lock

import (
	"io"

	"github.com/liamg/jfather"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type LockFile struct {
	Version int                     `json:"version"`
	Targets map[string]Dependencies `json:"dependencies"`
}

type Dependencies map[string]Dependency

type Dependency struct {
	Type         string `json:"type"`
	Resolved     string `json:"resolved"`
	StartLine    int
	EndLine      int
	Dependencies map[string]string `json:"dependencies,omitempty"`
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile LockFile
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to read packages.lock.json: %w", err)
	}
	if err := jfather.Unmarshal(input, &lockFile); err != nil {
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
				Locations: []ftypes.Location{
					{
						StartLine: packageContent.StartLine,
						EndLine:   packageContent.EndLine,
					},
				},
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

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *Dependency) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.NuGet, name, version)
}
