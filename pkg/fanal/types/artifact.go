package types

import (
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"

	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
)

type OS struct {
	Family string
	Name   string
	Eosl   bool `json:"EOSL,omitempty"`

	// This field is used for enhanced security maintenance programs such as Ubuntu ESM, Debian Extended LTS.
	Extended bool `json:"extended,omitempty"`
}

func (o *OS) Detected() bool {
	return o.Family != ""
}

// Merge merges OS version and enhanced security maintenance programs
func (o *OS) Merge(new OS) {
	if lo.IsEmpty(new) {
		return
	}

	switch {
	// OLE also has /etc/redhat-release and it detects OLE as RHEL by mistake.
	// In that case, OS must be overwritten with the content of /etc/oracle-release.
	// There is the same problem between Debian and Ubuntu.
	case o.Family == aos.RedHat, o.Family == aos.Debian:
		*o = new
	default:
		if o.Family == "" {
			o.Family = new.Family
		}
		if o.Name == "" {
			o.Name = new.Name
		}
		// Ubuntu has ESM program: https://ubuntu.com/security/esm
		// OS version and esm status are stored in different files.
		// We have to merge OS version after parsing these files.
		if o.Extended || new.Extended {
			o.Extended = true
		}
	}
}

type Repository struct {
	Family  string `json:",omitempty"`
	Release string `json:",omitempty"`
}

type Layer struct {
	Digest    string `json:",omitempty"`
	DiffID    string `json:",omitempty"`
	CreatedBy string `json:",omitempty"`
}

type Package struct {
	ID         string   `json:",omitempty"`
	Name       string   `json:",omitempty"`
	Version    string   `json:",omitempty"`
	Release    string   `json:",omitempty"`
	Epoch      int      `json:",omitempty"`
	Arch       string   `json:",omitempty"`
	SrcName    string   `json:",omitempty"`
	SrcVersion string   `json:",omitempty"`
	SrcRelease string   `json:",omitempty"`
	SrcEpoch   int      `json:",omitempty"`
	Licenses   []string `json:",omitempty"`
	Maintainer string   `json:",omitempty"`

	Modularitylabel string     `json:",omitempty"` // only for Red Hat based distributions
	BuildInfo       *BuildInfo `json:",omitempty"` // only for Red Hat

	Ref      string `json:",omitempty"` // identifier which can be used to reference the component elsewhere
	Indirect bool   `json:",omitempty"` // this package is direct dependency of the project or not

	// Dependencies of this package
	// Note:　it may have interdependencies, which may lead to infinite loops.
	DependsOn []string `json:",omitempty"`

	Layer Layer `json:",omitempty"`

	// Each package metadata have the file path, while the package from lock files does not have.
	FilePath string `json:",omitempty"`

	// Files provided by the package
	SystemInstalledFiles []string `json:",omitempty"`

	// lines from the lock file where the dependency is written
	Locations []Location `json:",omitempty"`
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
	Type string

	// Lock files have the file path here, while each package metadata do not have
	FilePath string `json:",omitempty"`

	// Libraries is a list of lang-specific packages
	Libraries []Package
}

type File struct {
	Type    string
	Path    string
	Content []byte
}

// ArtifactType represents a type of artifact
type ArtifactType string

const (
	ArtifactContainerImage   ArtifactType = "container_image"
	ArtifactFilesystem       ArtifactType = "filesystem"
	ArtifactRemoteRepository ArtifactType = "repository"
	ArtifactCycloneDX        ArtifactType = "cyclonedx"
	ArtifactSPDX             ArtifactType = "spdx"
	ArtifactAWSAccount       ArtifactType = "aws_account"
	ArtifactVM               ArtifactType = "vm"
)

// ArtifactReference represents a reference of container image, local filesystem and repository
type ArtifactReference struct {
	Name          string // image name, tar file name, directory or repository name
	Type          ArtifactType
	ID            string
	BlobIDs       []string
	ImageMetadata ImageMetadata

	// SBOM
	CycloneDX *CycloneDX
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

// ArtifactDetail is generated by applying blobs
type ArtifactDetail struct {
	OS                OS                 `json:",omitempty"`
	Repository        *Repository        `json:",omitempty"`
	Packages          Packages           `json:",omitempty"`
	Applications      []Application      `json:",omitempty"`
	Misconfigurations []Misconfiguration `json:",omitempty"`
	Secrets           []Secret           `json:",omitempty"`
	Licenses          []LicenseFile      `json:",omitempty"`

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages []Package `json:",omitempty"`

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []CustomResource `json:",omitempty"`
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
