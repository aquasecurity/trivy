package artifact

import (
	"context"
	"sort"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/misconf"
)

type Option struct {
	AnalyzerGroup     analyzer.Group // It is empty in OSS
	DisabledAnalyzers []analyzer.Type
	DisabledHandlers  []types.HandlerType
	SkipFiles         []string
	SkipDirs          []string
	OnlyDirs          []string
	FilePatterns      []string
	NoProgress        bool
	Insecure          bool
	Offline           bool
	AppDirs           []string
	SBOMSources       []string
	RekorURL          string
	Parallel          int
	AWSRegion         string
	AWSEndpoint       string
	FileChecksum      bool // For SPDX

	// Git repositories
	RepoBranch string
	RepoCommit string
	RepoTag    string

	// For image scanning
	ImageOption types.ImageOptions

	MisconfScannerOption misconf.ScannerOption
	SecretScannerOption  analyzer.SecretScannerOption
	LicenseScannerOption analyzer.LicenseScannerOption

	// File walk
	WalkOption WalkOption
}

// WalkOption is a struct that allows users to define a custom walking behavior.
// This option is only available when using Trivy as an imported library and not through CLI flags.
type WalkOption struct {
	ErrorCallback walker.ErrorCallback
}

func (o *Option) AnalyzerOptions() analyzer.AnalyzerOptions {
	return analyzer.AnalyzerOptions{
		Group:                o.AnalyzerGroup,
		FilePatterns:         o.FilePatterns,
		Parallel:             o.Parallel,
		DisabledAnalyzers:    o.DisabledAnalyzers,
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
	sort.Strings(o.SkipFiles)
	sort.Strings(o.SkipDirs)
	sort.Strings(o.FilePatterns)
	sort.Strings(o.OnlyDirs)
}

type Artifact interface {
	Inspect(ctx context.Context) (reference types.ArtifactReference, err error)
	Clean(reference types.ArtifactReference) error
}
