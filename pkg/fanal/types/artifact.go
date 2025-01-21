package types

import (
	"time"

	"github.com/samber/lo"
)

type OS struct {
	Family OSType
	Name   string
	Eosl   bool `json:"EOSL,omitempty"`

	// This field is used for enhanced security maintenance programs such as Ubuntu ESM, Debian Extended LTS.
	Extended bool `json:"extended,omitempty"`
}

func (o *OS) String() string {
	s := string(o.Family)
	if o.Name != "" {
		s += "/" + o.Name
	}
	return s
}

func (o *OS) Detected() bool {
	return o.Family != ""
}

// Normalize normalizes OS family names for backward compatibility
func (o *OS) Normalize() {
	if alias, ok := OSTypeAliases[o.Family]; ok {
		o.Family = alias
	}
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
	// When merging layers, there are cases when a layer contains an OS with an old name:
	//   - Cache contains a layer derived from an old version of Trivy.
	//   - `client` uses an old version of Trivy, but `server` is a new version of Trivy (for `client/server` mode).
	// So we need to normalize the OS name for backward compatibility.
	o.Normalize()
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

type PackageInfo struct {
	FilePath string
	Packages Packages
}

type Application struct {
	// e.g. bundler and pipenv
	Type LangType

	// Lock files have the file path here, while each package metadata do not have
	FilePath string `json:",omitempty"`

	// Packages is a list of lang-specific packages
	Packages Packages
}

type File struct {
	Type    string
	Path    string
	Content []byte
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
	Data     any
}
