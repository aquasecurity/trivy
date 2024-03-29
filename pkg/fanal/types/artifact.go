package types

import (
	"encoding/json"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

type OS struct {
	Family OSType
	Name   string
	Eosl   bool `json:"EOSL,omitempty"`

	// This field is used for enhanced security maintenance programs such as Ubuntu ESM, Debian Extended LTS.
	Extended bool `json:"extended,omitempty"`
}

func (o *OS) Detected() bool {
	return o.Family != ""
}

// Merge merges OS version and enhanced security maintenance programs
func (o *OS) Merge(newOS OS) {
	if lo.IsEmpty(newOS) {
		return
	}

	switch {
	// OLE also has /etc/redhat-release and it detects OLE as RHEL by mistake.
	// In that case, OS must be overwritten with the content of /etc/oracle-release.
	// There is the same problem between Debian and Ubuntu.
	case o.Family == RedHat, o.Family == Debian:
		*o = newOS
	default:
		if o.Family == "" {
			o.Family = newOS.Family
		}
		if o.Name == "" {
			o.Name = newOS.Name
		}
		// Ubuntu has ESM program: https://ubuntu.com/security/esm
		// OS version and esm status are stored in different files.
		// We have to merge OS version after parsing these files.
		if o.Extended || newOS.Extended {
			o.Extended = true
		}
	}
}

type Repository struct {
	Family  OSType `json:",omitempty"`
	Release string `json:",omitempty"`
}

type Layer struct {
	Digest    string `json:",omitempty"`
	DiffID    string `json:",omitempty"`
	CreatedBy string `json:",omitempty"`
}

type Package struct {
	ID         string        `json:",omitempty"`
	Name       string        `json:",omitempty"`
	Identifier PkgIdentifier `json:",omitempty"`
	Version    string        `json:",omitempty"`
	Release    string        `json:",omitempty"`
	Epoch      int           `json:",omitempty"`
	Arch       string        `json:",omitempty"`
	Dev        bool          `json:",omitempty"`
	SrcName    string        `json:",omitempty"`
	SrcVersion string        `json:",omitempty"`
	SrcRelease string        `json:",omitempty"`
	SrcEpoch   int           `json:",omitempty"`
	Licenses   []string      `json:",omitempty"`
	Maintainer string        `json:",omitempty"`

	Modularitylabel string     `json:",omitempty"` // only for Red Hat based distributions
	BuildInfo       *BuildInfo `json:",omitempty"` // only for Red Hat
	Indirect        bool       `json:",omitempty"` // this package is direct dependency of the project or not

	// Dependencies of this package
	// Note:　it may have interdependencies, which may lead to infinite loops.
	DependsOn []string `json:",omitempty"`

	Layer Layer `json:",omitempty"`

	// Each package metadata have the file path, while the package from lock files does not have.
	FilePath string `json:",omitempty"`

	// This is required when using SPDX formats. Otherwise, it will be empty.
	Digest digest.Digest `json:",omitempty"`

	// lines from the lock file where the dependency is written
	Locations []Location `json:",omitempty"`

	// Files installed by the package
	InstalledFiles []string `json:",omitempty"`
}

// PkgIdentifier represents a software identifiers in one of more of the supported formats.
type PkgIdentifier struct {
	PURL   *packageurl.PackageURL `json:"-"`
	BOMRef string                 `json:",omitempty"` // For CycloneDX
}

// MarshalJSON customizes the JSON encoding of PkgIdentifier.
func (id *PkgIdentifier) MarshalJSON() ([]byte, error) {
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
		Alias: (*Alias)(id),
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
	return id.PURL == nil && id.BOMRef == ""
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

// BuildInfo represents information under /root/buildinfo in RHEL
type BuildInfo struct {
	ContentSets []string `json:",omitempty"`
	Nvr         string   `json:",omitempty"`
	Arch        string   `json:",omitempty"`
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

type SrcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	BinaryNames []string `json:"binaryNames"`
}

type PackageInfo struct {
	FilePath string
	Packages Packages
}

type Application struct {
	// e.g. bundler and pipenv
	Type LangType

	// Lock files have the file path here, while each package metadata do not have
	FilePath string `json:",omitempty"`

	// Libraries is a list of lang-specific packages
	Libraries Packages
}

type File struct {
	Type    string
	Path    string
	Content []byte
}

// ArtifactType represents a type of artifact
type ArtifactType string

const (
	ArtifactContainerImage ArtifactType = "container_image"
	ArtifactFilesystem     ArtifactType = "filesystem"
	ArtifactRepository     ArtifactType = "repository"
	ArtifactCycloneDX      ArtifactType = "cyclonedx"
	ArtifactSPDX           ArtifactType = "spdx"
	ArtifactAWSAccount     ArtifactType = "aws_account"
	ArtifactVM             ArtifactType = "vm"
)

// ArtifactReference represents a reference of container image, local filesystem and repository
type ArtifactReference struct {
	Name          string // image name, tar file name, directory or repository name
	Type          ArtifactType
	ID            string
	BlobIDs       []string
	ImageMetadata ImageMetadata

	// SBOM
	BOM *core.BOM
}

type ImageMetadata struct {
	ID          string   // image ID
	DiffIDs     []string // uncompressed layer IDs
	RepoTags    []string
	RepoDigests []string
	ConfigFile  v1.ConfigFile
}

// ArtifactInfo is stored in cache
type ArtifactInfo struct {
	SchemaVersion int
	Architecture  string
	Created       time.Time
	DockerVersion string
	OS            string

	// Misconfiguration holds misconfiguration in container image config
	Misconfiguration *Misconfiguration `json:",omitempty"`

	// Secret holds secrets in container image config such as environment variables
	Secret *Secret `json:",omitempty"`

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages Packages `json:",omitempty"`
}

// BlobInfo is stored in cache
type BlobInfo struct {
	SchemaVersion int

	// Layer information
	Digest        string   `json:",omitempty"`
	DiffID        string   `json:",omitempty"`
	CreatedBy     string   `json:",omitempty"`
	OpaqueDirs    []string `json:",omitempty"`
	WhiteoutFiles []string `json:",omitempty"`

	// Analysis result
	OS                OS                 `json:",omitempty"`
	Repository        *Repository        `json:",omitempty"`
	PackageInfos      []PackageInfo      `json:",omitempty"`
	Applications      []Application      `json:",omitempty"`
	Misconfigurations []Misconfiguration `json:",omitempty"`
	Secrets           []Secret           `json:",omitempty"`
	Licenses          []LicenseFile      `json:",omitempty"`

	// Red Hat distributions have build info per layer.
	// This information will be embedded into packages when applying layers.
	// ref. https://redhat-connect.gitbook.io/partner-guide-for-adopting-red-hat-oval-v2/determining-common-platform-enumeration-cpe
	BuildInfo *BuildInfo `json:",omitempty"`

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []CustomResource `json:",omitempty"`
}

// ArtifactDetail represents the analysis result.
type ArtifactDetail struct {
	OS                OS                 `json:",omitempty"`
	Repository        *Repository        `json:",omitempty"`
	Packages          Packages           `json:",omitempty"`
	Applications      []Application      `json:",omitempty"`
	Misconfigurations []Misconfiguration `json:",omitempty"`
	Secrets           []Secret           `json:",omitempty"`
	Licenses          []LicenseFile      `json:",omitempty"`

	// ImageConfig has information from container image config
	ImageConfig ImageConfigDetail

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []CustomResource `json:",omitempty"`
}

// ImageConfigDetail has information from container image config
type ImageConfigDetail struct {
	// Packages are packages extracted from RUN instructions in history
	Packages []Package `json:",omitempty"`

	// Misconfiguration holds misconfigurations in container image config
	Misconfiguration *Misconfiguration `json:",omitempty"`

	// Secret holds secrets in container image config
	Secret *Secret `json:",omitempty"`
}

// ToBlobInfo is used to store a merged layer in cache.
func (a *ArtifactDetail) ToBlobInfo() BlobInfo {
	return BlobInfo{
		SchemaVersion: BlobJSONSchemaVersion,
		OS:            a.OS,
		Repository:    a.Repository,
		PackageInfos: []PackageInfo{
			{
				FilePath: "merged", // Set a dummy file path
				Packages: a.Packages,
			},
		},
		Applications:      a.Applications,
		Misconfigurations: a.Misconfigurations,
		Secrets:           a.Secrets,
		Licenses:          a.Licenses,
		CustomResources:   a.CustomResources,
	}
}

// CustomResource holds the analysis result from a custom analyzer.
// It is for extensibility and not used in OSS.
type CustomResource struct {
	Type     string
	FilePath string
	Layer    Layer
	Data     interface{}
}
