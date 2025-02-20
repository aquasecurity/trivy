package artifact

import (
	"context"
	"sort"

	"github.com/google/go-containerregistry/pkg/v1"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/misconf"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

type Option struct {
	Type              Type
	AnalyzerGroup     analyzer.Group // It is empty in OSS
	DisabledAnalyzers []analyzer.Type
	DisabledHandlers  []types.HandlerType
	FilePatterns      []string
	Parallel          int
	NoProgress        bool
	Insecure          bool
	Offline           bool
	AppDirs           []string
	SBOMSources       []string
	RekorURL          string
	AWSRegion         string
	AWSEndpoint       string
	FileChecksum      bool // For SPDX
	DetectionPriority types.DetectionPriority

	// Original is the original target location, e.g. "github.com/aquasecurity/trivy"
	// Currently, it is used only for remote git repositories
	Original string

	// Git repositories
	RepoBranch string
	RepoCommit string
	RepoTag    string

	// For image scanning
	ImageOption types.ImageOptions

	MisconfScannerOption misconf.ScannerOption
	SecretScannerOption  analyzer.SecretScannerOption
	LicenseScannerOption analyzer.LicenseScannerOption

	WalkerOption walker.Option
}

func (o *Option) AnalyzerOptions() analyzer.AnalyzerOptions {
	return analyzer.AnalyzerOptions{
		Group:                o.AnalyzerGroup,
		FilePatterns:         o.FilePatterns,
		Parallel:             o.Parallel,
		DisabledAnalyzers:    o.DisabledAnalyzers,
		DetectionPriority:    o.DetectionPriority,
		MisconfScannerOption: o.MisconfScannerOption,
		SecretScannerOption:  o.SecretScannerOption,
		LicenseScannerOption: o.LicenseScannerOption,
	}
}

func (o *Option) ConfigAnalyzerOptions() analyzer.ConfigAnalyzerOptions {
	return analyzer.ConfigAnalyzerOptions{
		FilePatterns:         o.FilePatterns,
		DisabledAnalyzers:    o.DisabledAnalyzers,
		MisconfScannerOption: o.MisconfScannerOption,
		SecretScannerOption:  o.SecretScannerOption,
	}
}

func (o *Option) Sort() {
	sort.Slice(o.DisabledAnalyzers, func(i, j int) bool {
		return o.DisabledAnalyzers[i] < o.DisabledAnalyzers[j]
	})
	sort.Strings(o.WalkerOption.SkipFiles)
	sort.Strings(o.WalkerOption.SkipDirs)
	sort.Strings(o.WalkerOption.OnlyDirs)
	sort.Strings(o.FilePatterns)
}

type Artifact interface {
	Inspect(ctx context.Context) (reference Reference, err error)
	Clean(reference Reference) error
}

// Type represents a type of artifact
type Type string

const (
	TypeContainerImage Type = "container_image"
	TypeFilesystem     Type = "filesystem"
	TypeRepository     Type = "repository"
	TypeCycloneDX      Type = "cyclonedx"
	TypeSPDX           Type = "spdx"
	TypeAWSAccount     Type = "aws_account"
	TypeVM             Type = "vm"
)

// Reference represents a reference of container image, local filesystem and repository
type Reference struct {
	Name          string // image name, tar file name, directory or repository name
	Type          Type
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
