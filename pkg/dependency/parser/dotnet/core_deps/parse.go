package core_deps

import (
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/liamg/jfather"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type dotNetDependencies struct {
	Libraries     map[string]dotNetLibrary     `json:"libraries"`
	RuntimeTarget RuntimeTarget                `json:"runtimeTarget"`
	Targets       map[string]map[string]Target `json:"targets"`
}

type dotNetLibrary struct {
	Type      string `json:"type"`
	StartLine int
	EndLine   int
}

type RuntimeTarget struct {
	Name string `json:"name"`
}

type Target struct {
	Runtime        any `json:"runtime"`
	RuntimeTargets any `json:"runtimeTargets"`
	Native         any `json:"native"`
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

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var depsFile dotNetDependencies

	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}
	if err = jfather.Unmarshal(input, &depsFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode .deps.json file: %w", err)
	}

	// Select target for RuntimeTarget
	target := depsFile.Targets[depsFile.RuntimeTarget.Name]

	var pkgs ftypes.Packages
	for nameVer, lib := range depsFile.Libraries {
		if !strings.EqualFold(lib.Type, "package") {
			continue
		}

		split := strings.Split(nameVer, "/")
		if len(split) != 2 {
			// Invalid name
			p.logger.Warn("Cannot parse .NET library version", log.String("library", nameVer))
			continue
		}

		pkgs = append(pkgs, ftypes.Package{
			ID:      dependency.ID(ftypes.DotNetCore, split[0], split[1]),
			Name:    split[0],
			Version: split[1],
			Locations: []ftypes.Location{
				{
					StartLine: lib.StartLine,
					EndLine:   lib.EndLine,
				},
			},
			// We're still not sure that we need to skip libraries built into .NETCore (or that we detect them correctly).
			// So we mark these libraries as Dev to skip the scan by default, but keep the options for displaying these libraries.
			Dev: p.isLibraryBuiltIntoNetCore(target, depsFile.RuntimeTarget.Name, nameVer),
		})
	}

	sort.Sort(pkgs)
	return pkgs, nil, nil
}

// isLibraryBuiltIntoNetCore returns true if library doesn't contain `runtime`, `runtimeTarget` and `native` sections.
// See https://github.com/aquasecurity/trivy/discussions/4282#discussioncomment-8830365 for more details.
func (p *Parser) isLibraryBuiltIntoNetCore(target map[string]Target, runtimeTargetName, library string) bool {
	// `Target` for `RuntimeTarget.Name` not found
	if target == nil {
		p.once.Do(func() {
			p.logger.Debug("Unable to find `Target` for Runtime Target Name. All dependencies from `libraries` section will be included in the report", log.String("RuntimeTarget", runtimeTargetName))
		})
		return false
	}
	lib, ok := target[library]
	// Selected target doesn't contain library
	if !ok {
		p.once.Do(func() {
			p.logger.Debug("Unable to determine that the library is built into .NET Core. Library not found in `Target` section.", log.String("RuntimeTarget", runtimeTargetName), log.String("Library", library))
		})
		return false
	}
	// Check that `runtime`, `runtimeTarget` and `native` sections are empty
	return lo.IsEmpty(lib)
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *dotNetLibrary) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}
