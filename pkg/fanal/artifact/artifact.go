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
	sort.Strings(o.FilePatterns)
}

type Artifact interface {
	Inspect(ctx context.Context) (reference types.ArtifactReference, err error)
	Clean(reference types.ArtifactReference) error
}
