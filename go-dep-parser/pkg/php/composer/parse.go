package composer

import (
	"io"
	"sort"
	"strings"

	"github.com/liamg/jfather"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type lockFile struct {
	Packages []packageInfo `json:"packages"`
}
type packageInfo struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Require   map[string]string `json:"require"`
	License   []string          `json:"license"`
	StartLine int
	EndLine   int
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile lockFile
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}
	if err = jfather.Unmarshal(input, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	libs := map[string]types.Library{}
	foundDeps := map[string][]string{}
	for _, pkg := range lockFile.Packages {
		lib := types.Library{
			ID:       utils.PackageID(pkg.Name, pkg.Version),
			Name:     pkg.Name,
			Version:  pkg.Version,
			Indirect: false, // composer.lock file doesn't have info about Direct/Indirect deps. Will think that all dependencies are Direct
			License:  strings.Join(pkg.License, ", "),
			Locations: []types.Location{
				{
					StartLine: pkg.StartLine,
					EndLine:   pkg.EndLine,
				},
			},
		}
		libs[lib.Name] = lib

		var dependsOn []string
		for depName := range pkg.Require {
			// Require field includes required php version, skip this
			// Also skip PHP extensions
			if depName == "php" || strings.HasPrefix(depName, "ext") {
				continue
			}
			dependsOn = append(dependsOn, depName) // field uses range of versions, so later we will fill in the versions from the libraries
		}
		if len(dependsOn) > 0 {
			foundDeps[lib.ID] = dependsOn
		}
	}

	// fill deps versions
	var deps []types.Dependency
	for libID, depsOn := range foundDeps {
		var dependsOn []string
		for _, depName := range depsOn {
			if lib, ok := libs[depName]; ok {
				dependsOn = append(dependsOn, lib.ID)
				continue
			}
			log.Logger.Debugf("unable to find version of %s", depName)
		}
		sort.Strings(dependsOn)
		deps = append(deps, types.Dependency{
			ID:        libID,
			DependsOn: dependsOn,
		})
	}

	libSlice := maps.Values(libs)
	sort.Sort(types.Libraries(libSlice))
	sort.Sort(types.Dependencies(deps))

	return libSlice, deps, nil
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *packageInfo) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}
