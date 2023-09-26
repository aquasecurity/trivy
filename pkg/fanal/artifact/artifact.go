package artifact

import (
	"context"
	"os"
	"sort"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

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
	FilePatterns      []string
	NoProgress        bool
	Insecure          bool
	Offline           bool
	AppDirs           []string
	SBOMSources       []string
	RekorURL          string
	Slow              bool // Lower CPU and memory
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

func (o *Option) Sort() {
	sort.Slice(o.DisabledAnalyzers, func(i, j int) bool {
		return o.DisabledAnalyzers[i] < o.DisabledAnalyzers[j]
	})
	sort.Strings(o.SkipFiles)
	sort.Strings(o.SkipDirs)
	sort.Strings(o.FilePatterns)
}

func (o *Option) ConfigFiles() []string {
	// data paths and policy paths are ignored because their own file systems are created for them
	return lo.Flatten(
		[][]string{
			o.MisconfScannerOption.TerraformTFVars,
			o.MisconfScannerOption.HelmFileValues,
			o.MisconfScannerOption.HelmValueFiles,
		},
	)
}

type Artifact interface {
	Inspect(ctx context.Context) (reference types.ArtifactReference, err error)
	Clean(reference types.ArtifactReference) error
}

func AddConfigFilesToFS(composite *analyzer.CompositeFS, opt Option) error {
	for _, configFile := range opt.ConfigFiles() {
		if _, err := os.Stat(configFile); err != nil {
			return xerrors.Errorf("config file %q not found: %w", configFile, err)
		}
		if err := composite.CreateLink(analyzer.TypeConfigFiles, "", configFile, configFile); err != nil {
			return xerrors.Errorf("failed to create link: %w", err)
		}
	}

	return nil
}
