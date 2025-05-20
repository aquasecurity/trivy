package julia

import (
	"io"
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type primitiveManifest struct {
	JuliaVersion   string                           `toml:"julia_version"`
	ManifestFormat string                           `toml:"manifest_format"`
	Dependencies   map[string][]primitiveDependency `toml:"deps"` // e.g. [[deps.Foo]]
}

type primitiveDependency struct {
	Dependencies toml.Primitive `toml:"deps"` // by name. e.g. deps = ["Foo"] or [deps.Foo.deps]
	UUID         string         `toml:"uuid"`
	Version      string         `toml:"version"` // not specified for stdlib packages, which are of the Julia version
	DependsOn    []string       `toml:"-"`       // list of dependent UUID's.
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var oldDeps map[string][]primitiveDependency
	var primMan primitiveManifest
	var manMetadata toml.MetaData
	decoder := toml.NewDecoder(r)
	// Try to read the old Manifest format. This can also read the v1.0 Manifest format, which we parse out later.
	var err error
	if manMetadata, err = decoder.Decode(&oldDeps); err != nil {
		if _, err = r.Seek(0, io.SeekStart); err != nil {
			return nil, nil, xerrors.Errorf("seek error: %w", err)
		}
		if manMetadata, err = decoder.Decode(&primMan); err != nil {
			return nil, nil, xerrors.Errorf("decode error: %w", err)
		}
	}

	// We can't know the Julia version on an old manifest.
	// All newer manifests include a manifest version and a julia version.
	if primMan.ManifestFormat == "" {
		primMan = primitiveManifest{
			JuliaVersion: "unknown",
			Dependencies: oldDeps,
		}
	}

	man, err := decodeManifest(&primMan, &manMetadata)
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to decode manifest dependencies: %w", err)
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, nil, xerrors.Errorf("seek error: %w", err)
	}

	// naive parser to get line numbers
	pkgParser := naivePkgParser{r: r}
	lineNumIdx := pkgParser.parse()

	var pkgs ftypes.Packages
	var deps ftypes.Dependencies
	for name, manifestDeps := range man.Dependencies {
		for _, manifestDep := range manifestDeps {
			version := depVersion(manifestDep.Version, man.JuliaVersion)
			pkgID := manifestDep.UUID
			pkg := ftypes.Package{
				ID:      pkgID,
				Name:    name,
				Version: version,
			}
			if pos, ok := lineNumIdx[manifestDep.UUID]; ok {
				pkg.Locations = []ftypes.Location{
					{
						StartLine: pos.start,
						EndLine:   pos.end,
					},
				}
			}

			pkgs = append(pkgs, pkg)

			if len(manifestDep.DependsOn) > 0 {
				deps = append(deps, ftypes.Dependency{
					ID:        pkgID,
					DependsOn: manifestDep.DependsOn,
				})
			}
		}
	}
	sort.Sort(pkgs)
	sort.Sort(deps)
	return pkgs, deps, nil
}

// Returns the effective version of the `dep`.
// stdlib packages do not have a version in the manifest because they are packaged with julia itself
func depVersion(depVersion, juliaVersion string) string {
	if depVersion == "" {
		return juliaVersion
	}
	return depVersion
}

// Decodes a primitive manifest using the metadata from parse time.
func decodeManifest(man *primitiveManifest, metadata *toml.MetaData) (*primitiveManifest, error) {
	// Decode each dependency into the new manifest
	for depName, primDeps := range man.Dependencies {
		var newPrimDeps []primitiveDependency
		for _, primDep := range primDeps {
			newPrimDep, err := decodeDependency(man, primDep, metadata)
			if err != nil {
				return nil, err
			}
			newPrimDeps = append(newPrimDeps, newPrimDep)
		}
		man.Dependencies[depName] = newPrimDeps
	}

	return man, nil
}

// Decodes a primitive dependency using the metadata from parse time.
func decodeDependency(man *primitiveManifest, dep primitiveDependency, metadata *toml.MetaData) (primitiveDependency, error) {
	// Try to decode as []string first where the manifest looks like deps = ["A", "B"]
	var possibleDeps []string
	err := metadata.PrimitiveDecode(dep.Dependencies, &possibleDeps)
	if err == nil {
		var possibleUuids []string
		for _, depName := range possibleDeps {
			primDep := man.Dependencies[depName]
			if len(primDep) == 0 {
				return primitiveDependency{}, xerrors.Errorf("Dependency %q has invalid format (parsed no deps): %s", depName, primDep)
			}
			if len(primDep) > 1 {
				return primitiveDependency{}, xerrors.Errorf("Dependency %q has invalid format (parsed multiple deps): %s", depName, primDep)
			}
			possibleUuids = append(possibleUuids, primDep[0].UUID)
		}
		sort.Strings(possibleUuids)
		dep.DependsOn = possibleUuids
		return dep, nil
	}

	// The other possibility is a map where the manifest looks like
	// [deps.A.deps]
	// B = "..."
	var possibleDepsMap map[string]string
	err = metadata.PrimitiveDecode(dep.Dependencies, &possibleDepsMap)
	if err == nil {
		possibleUuids := lo.Values(possibleDepsMap)
		sort.Strings(possibleUuids)
		dep.DependsOn = possibleUuids
		return dep, nil
	}

	// We don't know what the shape of the data is -- i.e. an invalid manifest
	return primitiveDependency{}, err
}
