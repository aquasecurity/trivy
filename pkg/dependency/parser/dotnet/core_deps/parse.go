package core_deps

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type dotNetDependencies struct {
	Libraries     map[string]dotNetLibrary        `json:"libraries"`
	RuntimeTarget RuntimeTarget                   `json:"runtimeTarget"`
	Targets       map[string]map[string]TargetLib `json:"targets"`
}

type dotNetLibrary struct {
	Type string `json:"type"`
	xjson.Location
}

type RuntimeTarget struct {
	Name string `json:"name"`
}

type TargetLib struct {
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

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var depsFile dotNetDependencies
	if err := xjson.UnmarshalRead(r, &depsFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode .deps.json file: %w", err)
	}

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

		// Take target libraries for RuntimeTarget
		if targetLibs, ok := depsFile.Targets[depsFile.RuntimeTarget.Name]; !ok {
			// If the target is not found, take all dependencies
			p.once.Do(func() {
				p.logger.Debug("Unable to find `Target` for Runtime Target Name. All dependencies from `libraries` section will be included in the report", log.String("Runtime Target Name", depsFile.RuntimeTarget.Name))
			})
		} else if !p.isRuntimeLibrary(targetLibs, nameVer) {
			// Skip non-runtime libraries
			// cf. https://github.com/aquasecurity/trivy/pull/7039#discussion_r1674566823
			continue
		}

		pkgs = append(pkgs, ftypes.Package{
			ID:        dependency.ID(ftypes.DotNetCore, split[0], split[1]),
			Name:      split[0],
			Version:   split[1],
			Locations: []ftypes.Location{ftypes.Location(lib.Location)},
		})
	}

	sort.Sort(pkgs)
	return pkgs, nil, nil
}

// isRuntimeLibrary returns true if library contains `runtime`, `runtimeTarget` or `native` sections, or if the library is missing from `targetLibs`.
// See https://github.com/aquasecurity/trivy/discussions/4282#discussioncomment-8830365 for more details.
func (p *Parser) isRuntimeLibrary(targetLibs map[string]TargetLib, library string) bool {
	lib, ok := targetLibs[library]
	// Selected target doesn't contain library
	// Mark these libraries as runtime to avoid mistaken omission
	if !ok {
		p.once.Do(func() {
			p.logger.Debug("Unable to determine that this is runtime library. Library not found in `Target` section.", log.String("Library", library))
		})
		return true
	}
	// Check that `runtime`, `runtimeTarget` and `native` sections are not empty
	return !lo.IsEmpty(lib)
}
