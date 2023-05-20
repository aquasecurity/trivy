package julia

import (
	"io"
	"sort"

	"github.com/BurntSushi/toml"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"

	"golang.org/x/xerrors"
)

type juliaPkg struct {
	Deps    []string `toml:"dependencies,omitempty"`
	Name    string   `toml:"name"`
	UUID    string   `toml:"uuid"`
	Version string   `toml:"version"`
}
type Manifest struct {
	JuliaVersion   string           `toml:"julia_version"`
	ManifestFormat string           `toml:"manifest_format"`
	Deps           map[string][]Dep `toml:"deps"`
}
type Dep struct {
	Deps    []string `toml:"deps"` // e.g. [[deps.Foo]]
	UUID    string   `toml:"uuid"`
	Version string   `toml:"version"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var manifest Manifest
	decoder := toml.NewDecoder(r)
	if _, err := decoder.Decode(&manifest); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, nil, xerrors.Errorf("seek error: %w", err)
	}

	// naive parser to get line numbers
	pkgParser := naivePkgParser{r: r}
	lineNumIdx := pkgParser.parse()

	var libs []types.Library
	var deps []types.Dependency
	for name, manifestDeps := range manifest.Deps {
		manifestDep := manifestDeps[0]

		// stdlib packages do not have a version set because they are packaged with julia itself
		version := manifestDep.Version
		if len(version) == 0 {
			version = manifest.JuliaVersion
		}

		lib := types.Library{
			ID:      manifestDep.UUID,
			Name:    name,
			Version: version,
		}
		if pos, ok := lineNumIdx[manifestDep.UUID]; ok {
			lib.Locations = []types.Location{{StartLine: pos.start, EndLine: pos.end}}
		}

		libs = append(libs, lib)
		dep := parseDependencies(manifestDep.UUID, manifestDep, manifest.Deps)
		if dep != nil {
			deps = append(deps, *dep)
		}
	}
	sort.Sort(types.Libraries(libs))
	sort.Sort(types.Dependencies(deps))
	return libs, deps, nil
}
func parseDependencies(pkgId string, dep Dep, deps map[string][]Dep) *types.Dependency {
	var dependOn []string

	for _, pkgDep := range dep.Deps {
		dependOn = append(dependOn, deps[pkgDep][0].UUID)
	}
	if len(dependOn) > 0 {
		sort.Strings(dependOn)
		return &types.Dependency{
			ID:        pkgId,
			DependsOn: dependOn,
		}
	} else {
		return nil
	}
}
