package lock

import (
	"io"

	"github.com/liamg/jfather"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
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

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile LockFile
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to read packages.lock.json: %w", err)
	}
	if err := jfather.Unmarshal(input, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode packages.lock.json: %w", err)
	}

	libs := make([]types.Library, 0)
	depsMap := make(map[string][]string)
	for _, targetContent := range lockFile.Targets {
		for packageName, packageContent := range targetContent {
			// If package type is "project", it is the actual project, and we skip it.
			if packageContent.Type == "Project" {
				continue
			}

			depId := utils.PackageID(packageName, packageContent.Resolved)

			lib := types.Library{
				ID:       depId,
				Name:     packageName,
				Version:  packageContent.Resolved,
				Indirect: packageContent.Type != "Direct",
				Locations: []types.Location{
					{
						StartLine: packageContent.StartLine,
						EndLine:   packageContent.EndLine,
					},
				},
			}
			libs = append(libs, lib)

			var dependsOn []string

			for depName := range packageContent.Dependencies {
				dependsOn = append(dependsOn, utils.PackageID(depName, targetContent[depName].Resolved))
			}

			if savedDependsOn, ok := depsMap[depId]; ok {
				dependsOn = utils.UniqueStrings(append(dependsOn, savedDependsOn...))
			}

			if len(dependsOn) > 0 {
				depsMap[depId] = dependsOn
			}
		}
	}

	deps := make([]types.Dependency, 0)
	for depId, dependsOn := range depsMap {
		dep := types.Dependency{
			ID:        depId,
			DependsOn: dependsOn,
		}
		deps = append(deps, dep)
	}

	return utils.UniqueLibraries(libs), deps, nil
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
