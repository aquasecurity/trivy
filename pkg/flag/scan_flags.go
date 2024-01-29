package flag

import (
	"runtime"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

var (
	SkipDirsFlag = Flag{
		Name:       "skip-dirs",
		ConfigName: "scan.skip-dirs",
		Default:    []string{},
		Usage:      "specify the directories or glob patterns to skip",
	}
	SkipFilesFlag = Flag{
		Name:       "skip-files",
		ConfigName: "scan.skip-files",
		Default:    []string{},
		Usage:      "specify the files or glob patterns to skip",
	}
	OnlyDirsFlag = Flag{
		Name:       "only-dirs",
		ConfigName: "scan.only-dirs",
		Default:    []string{},
		Usage:      "specify the directories where the traversal is allowed",
	}
	OfflineScanFlag = Flag{
		Name:       "offline-scan",
		ConfigName: "scan.offline",
		Default:    false,
		Usage:      "do not issue API requests to identify dependencies",
	}
	ScannersFlag = Flag{
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
		ValueNormalize: func(s string) string {
			switch s {
			case "vulnerability":
				return string(types.VulnerabilityScanner)
			case "misconf", "misconfiguration":
				return string(types.MisconfigScanner)
			case "config":
				log.Logger.Warn("'--scanner config' is deprecated. Use '--scanner misconfig' instead. See https://github.com/aquasecurity/trivy/discussions/5586 for the detail.")
				return string(types.MisconfigScanner)
			}
			return s
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
	FilePatternsFlag = Flag{
		Name:       "file-patterns",
		ConfigName: "scan.file-patterns",
		Default:    []string{},
		Usage:      "specify config file patterns",
	}
	SlowFlag = Flag{
		Name:       "slow",
		ConfigName: "scan.slow",
		Default:    false,
		Usage:      "scan over time with lower CPU and memory utilization",
		Deprecated: true,
	}
	ParallelFlag = Flag{
		Name:       "parallel",
		ConfigName: "scan.parallel",
		Default:    5,
		Usage:      "number of goroutines enabled for parallel scanning, set 0 to auto-detect parallelism",
	}
	SBOMSourcesFlag = Flag{
		Name:       "sbom-sources",
		ConfigName: "scan.sbom-sources",
		Default:    []string{},
		Values:     []string{"oci", "rekor"},
		Usage:      "[EXPERIMENTAL] try to retrieve SBOM from the specified sources",
	}
	RekorURLFlag = Flag{
		Name:       "rekor-url",
		ConfigName: "scan.rekor-url",
		Default:    "https://rekor.sigstore.dev",
		Usage:      "[EXPERIMENTAL] address of rekor STL server",
	}
	IncludeDevDepsFlag = Flag{
		Name:       "include-dev-deps",
		ConfigName: "include-dev-deps",
		Default:    false,
		Usage:      "include development dependencies in the report (supported: npm, yarn)",
	}
)

type ScanFlagGroup struct {
	SkipDirs       *Flag
	SkipFiles      *Flag
	OnlyDirs       *Flag
	OfflineScan    *Flag
	Scanners       *Flag
	FilePatterns   *Flag
	Slow           *Flag // deprecated
	Parallel       *Flag
	SBOMSources    *Flag
	RekorURL       *Flag
	IncludeDevDeps *Flag
}

type ScanOptions struct {
	Target         string
	SkipDirs       []string
	SkipFiles      []string
	OnlyDirs       []string
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
		SkipDirs:       &SkipDirsFlag,
		SkipFiles:      &SkipFilesFlag,
		OnlyDirs:       &OnlyDirsFlag,
		OfflineScan:    &OfflineScanFlag,
		Scanners:       &ScannersFlag,
		FilePatterns:   &FilePatternsFlag,
		Parallel:       &ParallelFlag,
		SBOMSources:    &SBOMSourcesFlag,
		RekorURL:       &RekorURLFlag,
		IncludeDevDeps: &IncludeDevDepsFlag,
		Slow:           &SlowFlag,
	}
}

func (f *ScanFlagGroup) Name() string {
	return "Scan"
}

func (f *ScanFlagGroup) Flags() []*Flag {
	return []*Flag{
		f.SkipDirs,
		f.SkipFiles,
		f.OnlyDirs,
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
	var target string
	if len(args) == 1 {
		target = args[0]
	}

	parallel := getInt(f.Parallel)
	if f.Parallel != nil && parallel == 0 {
		log.Logger.Infof("Set '--parallel' to the number of CPUs (%d)", runtime.NumCPU())
		parallel = runtime.NumCPU()
	}

	return ScanOptions{
		Target:         target,
		SkipDirs:       getStringSlice(f.SkipDirs),
		SkipFiles:      getStringSlice(f.SkipFiles),
		OnlyDirs:       getStringSlice(f.OnlyDirs),
		OfflineScan:    getBool(f.OfflineScan),
		Scanners:       getUnderlyingStringSlice[types.Scanner](f.Scanners),
		FilePatterns:   getStringSlice(f.FilePatterns),
		Parallel:       parallel,
		SBOMSources:    getStringSlice(f.SBOMSources),
		RekorURL:       getString(f.RekorURL),
		IncludeDevDeps: getBool(f.IncludeDevDeps),
	}, nil
}
