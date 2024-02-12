package flag

import (
	"runtime"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

var (
	SkipDirsFlag = Flag[[]string]{
		Name:       "skip-dirs",
		ConfigName: "scan.skip-dirs",
		Usage:      "specify the directories or glob patterns to skip",
	}
	SkipFilesFlag = Flag[[]string]{
		Name:       "skip-files",
		ConfigName: "scan.skip-files",
		Default:    []string{},
		Usage:      "specify the files or glob patterns to skip",
	}
	OfflineScanFlag = Flag[bool]{
		Name:       "offline-scan",
		ConfigName: "scan.offline",
		Usage:      "do not issue API requests to identify dependencies",
	}
	ScannersFlag = Flag[[]string]{
		Name:       "scanners",
		ConfigName: "scan.scanners",
		Default: xstrings.ToStringSlice(types.Scanners{
			types.VulnerabilityScanner,
			types.SecretScanner,
		}),
		Values: xstrings.ToStringSlice(types.Scanners{
			types.VulnerabilityScanner,
			types.MisconfigScanner,
			types.SecretScanner,
			types.LicenseScanner,
		}),
		ValueNormalize: func(ss []string) []string {
			return lo.Map(ss, func(s string, _ int) string {
				switch s {
				case "vulnerability":
					return string(types.VulnerabilityScanner)
				case "misconf", "misconfiguration":
					return string(types.MisconfigScanner)
				case "config":
					log.Logger.Warn("'--scanners config' is deprecated. Use '--scanners misconfig' instead. See https://github.com/aquasecurity/trivy/discussions/5586 for the detail.")
					return string(types.MisconfigScanner)
				}
				return s
			})
		},
		Aliases: []Alias{
			{
				Name:       "security-checks",
				ConfigName: "scan.security-checks",
				Deprecated: true, // --security-checks was renamed to --scanners
			},
		},
		Usage: "comma-separated list of what security issues to detect",
	}
	FilePatternsFlag = Flag[[]string]{
		Name:       "file-patterns",
		ConfigName: "scan.file-patterns",
		Usage:      "specify config file patterns",
	}
	SlowFlag = Flag[bool]{
		Name:       "slow",
		ConfigName: "scan.slow",
		Default:    false,
		Usage:      "scan over time with lower CPU and memory utilization",
		Deprecated: true,
	}
	ParallelFlag = Flag[int]{
		Name:       "parallel",
		ConfigName: "scan.parallel",
		Default:    5,
		Usage:      "number of goroutines enabled for parallel scanning, set 0 to auto-detect parallelism",
	}
	SBOMSourcesFlag = Flag[[]string]{
		Name:       "sbom-sources",
		ConfigName: "scan.sbom-sources",
		Values: []string{
			"oci",
			"rekor",
		},
		Usage: "[EXPERIMENTAL] try to retrieve SBOM from the specified sources",
	}
	RekorURLFlag = Flag[string]{
		Name:       "rekor-url",
		ConfigName: "scan.rekor-url",
		Default:    "https://rekor.sigstore.dev",
		Usage:      "[EXPERIMENTAL] address of rekor STL server",
	}
	IncludeDevDepsFlag = Flag[bool]{
		Name:       "include-dev-deps",
		ConfigName: "include-dev-deps",
		Usage:      "include development dependencies in the report (supported: npm, yarn)",
	}
)

type ScanFlagGroup struct {
	SkipDirs       *Flag[[]string]
	SkipFiles      *Flag[[]string]
	OfflineScan    *Flag[bool]
	Scanners       *Flag[[]string]
	FilePatterns   *Flag[[]string]
	Slow           *Flag[bool] // deprecated
	Parallel       *Flag[int]
	SBOMSources    *Flag[[]string]
	RekorURL       *Flag[string]
	IncludeDevDeps *Flag[bool]
}

type ScanOptions struct {
	Target         string
	SkipDirs       []string
	SkipFiles      []string
	OfflineScan    bool
	Scanners       types.Scanners
	FilePatterns   []string
	Parallel       int
	SBOMSources    []string
	RekorURL       string
	IncludeDevDeps bool
}

func NewScanFlagGroup() *ScanFlagGroup {
	return &ScanFlagGroup{
		SkipDirs:       SkipDirsFlag.Clone(),
		SkipFiles:      SkipFilesFlag.Clone(),
		OfflineScan:    OfflineScanFlag.Clone(),
		Scanners:       ScannersFlag.Clone(),
		FilePatterns:   FilePatternsFlag.Clone(),
		Parallel:       ParallelFlag.Clone(),
		SBOMSources:    SBOMSourcesFlag.Clone(),
		RekorURL:       RekorURLFlag.Clone(),
		IncludeDevDeps: IncludeDevDepsFlag.Clone(),
		Slow:           SlowFlag.Clone(),
	}
}

func (f *ScanFlagGroup) Name() string {
	return "Scan"
}

func (f *ScanFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.SkipDirs,
		f.SkipFiles,
		f.OfflineScan,
		f.Scanners,
		f.FilePatterns,
		f.Slow,
		f.Parallel,
		f.SBOMSources,
		f.RekorURL,
		f.IncludeDevDeps,
	}
}

func (f *ScanFlagGroup) ToOptions(args []string) (ScanOptions, error) {
	if err := parseFlags(f); err != nil {
		return ScanOptions{}, err
	}

	var target string
	if len(args) == 1 {
		target = args[0]
	}

	parallel := f.Parallel.Value()
	if f.Parallel != nil && parallel == 0 {
		log.Logger.Infof("Set '--parallel' to the number of CPUs (%d)", runtime.NumCPU())
		parallel = runtime.NumCPU()
	}

	return ScanOptions{
		Target:         target,
		SkipDirs:       f.SkipDirs.Value(),
		SkipFiles:      f.SkipFiles.Value(),
		OfflineScan:    f.OfflineScan.Value(),
		Scanners:       xstrings.ToTSlice[types.Scanner](f.Scanners.Value()),
		FilePatterns:   f.FilePatterns.Value(),
		Parallel:       parallel,
		SBOMSources:    f.SBOMSources.Value(),
		RekorURL:       f.RekorURL.Value(),
		IncludeDevDeps: f.IncludeDevDeps.Value(),
	}, nil
}
