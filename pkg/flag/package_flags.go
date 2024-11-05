package flag

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

var (
	IncludeDevDepsFlag = Flag[bool]{
		Name:       "include-dev-deps",
		ConfigName: "pkg.include-dev-deps",
		Usage:      "include development dependencies in the report (supported: npm, yarn)",
	}
	PkgTypesFlag = Flag[[]string]{
		Name:       "pkg-types",
		ConfigName: "pkg.types",
		Default:    types.PkgTypes,
		Values:     types.PkgTypes,
		Usage:      "list of package types",
		Aliases: []Alias{
			{
				Name:       "vuln-type",
				ConfigName: "vulnerability.type",
				Deprecated: true, // --vuln-type was renamed to --pkg-types
			},
		},
	}
	PkgRelationshipsFlag = Flag[[]string]{
		Name:       "pkg-relationships",
		ConfigName: "pkg.relationships",
		Default:    xstrings.ToStringSlice(ftypes.Relationships),
		Values:     xstrings.ToStringSlice(ftypes.Relationships),
		Usage:      "list of package relationships",
	}
)

// PackageFlagGroup composes common package flag structs.
// These flags affect both SBOM and vulnerability scanning.
type PackageFlagGroup struct {
	IncludeDevDeps   *Flag[bool]
	PkgTypes         *Flag[[]string]
	PkgRelationships *Flag[[]string]
}

type PackageOptions struct {
	IncludeDevDeps   bool
	PkgTypes         []string
	PkgRelationships []ftypes.Relationship
}

func NewPackageFlagGroup() *PackageFlagGroup {
	return &PackageFlagGroup{
		IncludeDevDeps:   IncludeDevDepsFlag.Clone(),
		PkgTypes:         PkgTypesFlag.Clone(),
		PkgRelationships: PkgRelationshipsFlag.Clone(),
	}
}

func (f *PackageFlagGroup) Name() string {
	return "Package"
}

func (f *PackageFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.IncludeDevDeps,
		f.PkgTypes,
		f.PkgRelationships,
	}
}

func (f *PackageFlagGroup) ToOptions() (PackageOptions, error) {
	if err := parseFlags(f); err != nil {
		return PackageOptions{}, err
	}

	var relationships []ftypes.Relationship
	for _, r := range f.PkgRelationships.Value() {
		relationship, err := ftypes.NewRelationship(r)
		if err != nil {
			return PackageOptions{}, err
		}
		relationships = append(relationships, relationship)
	}

	return PackageOptions{
		IncludeDevDeps:   f.IncludeDevDeps.Value(),
		PkgTypes:         f.PkgTypes.Value(),
		PkgRelationships: relationships,
	}, nil
}
