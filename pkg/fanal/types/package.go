package types

import (
	"encoding/json"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/digest"
)

type Relationship int

const (
	RelationshipUnknown Relationship = iota
	RelationshipRoot
	RelationshipWorkspace // For maven `modules`. TODO use it for cargo and npm workspaces
	RelationshipDirect
	RelationshipIndirect
)

var (
	Relationships = []Relationship{
		RelationshipUnknown,
		RelationshipRoot,
		RelationshipWorkspace,
		RelationshipDirect,
		RelationshipIndirect,
	}

	relationshipNames = [...]string{
		"unknown",
		"root",
		"workspace",
		"direct",
		"indirect",
	}
)

func NewRelationship(s string) (Relationship, error) {
	for i, name := range relationshipNames {
		if s == name {
			return Relationship(i), nil
		}
	}
	return RelationshipUnknown, xerrors.Errorf("invalid relationship (%s)", s)
}

func (r Relationship) String() string {
	if r <= RelationshipUnknown || int(r) >= len(relationshipNames) {
		return "unknown"
	}
	return relationshipNames[r]
}

func (r Relationship) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r *Relationship) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for i, name := range relationshipNames {
		if s == name {
			*r = Relationship(i)
			return nil
		}
	}
	return xerrors.Errorf("invalid relationship (%s)", s)
}

// PkgIdentifier represents a software identifiers in one of more of the supported formats.
type PkgIdentifier struct {
	UID    string                 `json:",omitempty"` // Calculated by the package struct
	PURL   *packageurl.PackageURL `json:"-"`
	BOMRef string                 `json:",omitempty"` // For CycloneDX
}

// MarshalJSON customizes the JSON encoding of PkgIdentifier.
func (id PkgIdentifier) MarshalJSON() ([]byte, error) {
	var p string
	if id.PURL != nil {
		p = id.PURL.String()
	}

	type Alias PkgIdentifier
	return json.Marshal(&struct {
		PURL string `json:",omitempty"`
		*Alias
	}{
		PURL:  p,
		Alias: (*Alias)(&id),
	})
}

// UnmarshalJSON customizes the JSON decoding of PkgIdentifier.
func (id *PkgIdentifier) UnmarshalJSON(data []byte) error {
	type Alias PkgIdentifier
	aux := &struct {
		PURL string `json:",omitempty"`
		*Alias
	}{
		Alias: (*Alias)(id),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.PURL != "" {
		p, err := packageurl.FromString(aux.PURL)
		if err != nil {
			return err
		} else if len(p.Qualifiers) == 0 {
			p.Qualifiers = nil
		}
		id.PURL = &p
	}

	return nil
}

func (id *PkgIdentifier) Empty() bool {
	return id.UID == "" && id.PURL == nil && id.BOMRef == ""
}

func (id *PkgIdentifier) Match(s string) bool {
	// Encode string as PURL
	if strings.HasPrefix(s, "pkg:") {
		if p, err := packageurl.FromString(s); err == nil {
			s = p.String()
		}
	}

	switch {
	case id.BOMRef == s:
		return true
	case id.PURL != nil && id.PURL.String() == s:
		return true
	}
	return false
}

type Location struct {
	StartLine int `json:",omitempty"`
	EndLine   int `json:",omitempty"`
}

type Locations []Location

func (locs Locations) Len() int { return len(locs) }
func (locs Locations) Less(i, j int) bool {
	return locs[i].StartLine < locs[j].StartLine
}
func (locs Locations) Swap(i, j int) { locs[i], locs[j] = locs[j], locs[i] }

type ExternalRef struct {
	Type RefType
	URL  string
}

type RefType string

const (
	RefVCS   RefType = "vcs"
	RefOther RefType = "other"
)

// BuildInfo represents information under /root/buildinfo in RHEL
type BuildInfo struct {
	ContentSets []string `json:",omitempty"`
	Nvr         string   `json:",omitempty"`
	Arch        string   `json:",omitempty"`
}

type Package struct {
	ID                 string        `json:",omitempty"`
	Name               string        `json:",omitempty"`
	Identifier         PkgIdentifier `json:",omitempty"`
	Version            string        `json:",omitempty"`
	Release            string        `json:",omitempty"`
	Epoch              int           `json:",omitempty"`
	Arch               string        `json:",omitempty"`
	Dev                bool          `json:",omitempty"`
	SrcName            string        `json:",omitempty"`
	SrcVersion         string        `json:",omitempty"`
	SrcRelease         string        `json:",omitempty"`
	SrcEpoch           int           `json:",omitempty"`
	Licenses           []string      `json:",omitempty"`
	Maintainer         string        `json:",omitempty"`
	ExternalReferences []ExternalRef `json:"-" hash:"ignore"`

	Modularitylabel string     `json:",omitempty"` // only for Red Hat based distributions
	BuildInfo       *BuildInfo `json:",omitempty"` // only for Red Hat

	Indirect     bool         `json:",omitempty"` // Deprecated: Use relationship. Kept for backward compatibility.
	Relationship Relationship `json:",omitempty"`

	// Dependencies of this package
	// Note:　it may have interdependencies, which may lead to infinite loops.
	DependsOn []string `json:",omitempty"`

	Layer Layer `json:",omitempty"`

	// Each package metadata have the file path, while the package from lock files does not have.
	FilePath string `json:",omitempty"`

	// This is required when using SPDX formats. Otherwise, it will be empty.
	Digest digest.Digest `json:",omitempty"`

	// lines from the lock file where the dependency is written
	Locations Locations `json:",omitempty"`

	// Files installed by the package
	InstalledFiles []string `json:",omitempty"`
}

func (pkg *Package) Empty() bool {
	return pkg.Name == "" || pkg.Version == ""
}

type Packages []Package

func (pkgs Packages) Len() int {
	return len(pkgs)
}

func (pkgs Packages) Swap(i, j int) {
	pkgs[i], pkgs[j] = pkgs[j], pkgs[i]
}

func (pkgs Packages) Less(i, j int) bool {
	switch {
	case pkgs[i].Relationship != pkgs[j].Relationship:
		if pkgs[i].Relationship == RelationshipUnknown {
			return false
		} else if pkgs[j].Relationship == RelationshipUnknown {
			return true
		}
		return pkgs[i].Relationship < pkgs[j].Relationship
	case pkgs[i].Name != pkgs[j].Name:
		return pkgs[i].Name < pkgs[j].Name
	case pkgs[i].Version != pkgs[j].Version:
		return pkgs[i].Version < pkgs[j].Version
	}
	return pkgs[i].FilePath < pkgs[j].FilePath
}

// ParentDeps returns a map where the keys are package IDs and the values are the packages
// that depend on the respective package ID (parent dependencies).
func (pkgs Packages) ParentDeps() map[string]Packages {
	parents := make(map[string]Packages)
	for _, pkg := range pkgs {
		for _, dependOn := range pkg.DependsOn {
			parents[dependOn] = append(parents[dependOn], pkg)
		}
	}

	for k, v := range parents {
		parents[k] = lo.UniqBy(v, func(pkg Package) string {
			return pkg.ID
		})
	}
	return parents
}

type Dependency struct {
	ID        string
	DependsOn []string
}

type Dependencies []Dependency

func (deps Dependencies) Len() int { return len(deps) }
func (deps Dependencies) Less(i, j int) bool {
	return deps[i].ID < deps[j].ID
}
func (deps Dependencies) Swap(i, j int) { deps[i], deps[j] = deps[j], deps[i] }
