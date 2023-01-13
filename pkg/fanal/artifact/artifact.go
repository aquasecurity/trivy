package artifact

import (
	"context"
	"sort"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	misconf "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
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
	Offline           bool
	InsecureSkipTLS   bool
	AppDirs           []string
	RepoBranch        string
	RepoCommit        string
	RepoTag           string
	SBOMSources       []string
	RekorURL          string
	Platform          string
	Slow              bool // Lower CPU and memory
	AWSRegion         string

	MisconfScannerOption misconf.ScannerOption
	SecretScannerOption  analyzer.SecretScannerOption
	LicenseScannerOption analyzer.LicenseScannerOption
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
