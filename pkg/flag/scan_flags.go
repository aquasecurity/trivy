package flag

import (
	"runtime"
	"slices"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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
		Name:          "offline-scan",
		ConfigName:    "scan.offline",
		Usage:         "do not issue API requests to identify dependencies",
		TelemetrySafe: true,
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
					log.Warn("'--scanners config' is deprecated. Use '--scanners misconfig' instead. See https://github.com/aquasecurity/trivy/discussions/5586 for the detail.")
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
		Usage:         "comma-separated list of what security issues to detect",
		TelemetrySafe: true,
	}
	FilePatternsFlag = Flag[[]string]{
		Name:       "file-patterns",
		ConfigName: "scan.file-patterns",
		Usage:      "specify config file patterns",
	}
	SlowFlag = Flag[bool]{
		Name:          "slow",
		ConfigName:    "scan.slow",
		Default:       false,
		Usage:         "scan over time with lower CPU and memory utilization",
		Deprecated:    `Use "--parallel 1" instead.`,
		TelemetrySafe: true,
	}
	ParallelFlag = Flag[int]{
		Name:          "parallel",
		ConfigName:    "scan.parallel",
		Default:       5,
		Usage:         "number of goroutines enabled for parallel scanning, set 0 to auto-detect parallelism",
		TelemetrySafe: true,
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
	DetectionPriority = Flag[string]{
		Name:       "detection-priority",
		ConfigName: "scan.detection-priority",
		Default:    string(ftypes.PriorityPrecise),
		Values: xstrings.ToStringSlice([]ftypes.DetectionPriority{
			ftypes.PriorityPrecise,
			ftypes.PriorityComprehensive,
		}),
		Usage: `specify the detection priority:
  - "precise": Prioritizes precise by minimizing false positives.
  - "comprehensive": Aims to detect more security findings at the cost of potential false positives.
`,
		TelemetrySafe: true,
	}
	DistroFlag = Flag[string]{
		Name:          "distro",
		ConfigName:    "scan.distro",
		Usage:         "[EXPERIMENTAL] specify a distribution, <family>/<version>",
		TelemetrySafe: true,
	}
	SkipVersionCheckFlag = Flag[bool]{
		Name:          "skip-version-check",
		ConfigName:    "scan.skip-version-check",
		Usage:         "suppress notices about version updates and Trivy announcements",
		TelemetrySafe: true,
	}
	DisableTelemetryFlag = Flag[bool]{
		Name:       "disable-telemetry",
		ConfigName: "scan.disable-telemetry",
		Usage:      "disable sending anonymous usage data to Aqua",
	}
)

type ScanFlagGroup struct {
	SkipDirs          *Flag[[]string]
	SkipFiles         *Flag[[]string]
	OfflineScan       *Flag[bool]
	Scanners          *Flag[[]string]
	FilePatterns      *Flag[[]string]
	Slow              *Flag[bool] // deprecated
	Parallel          *Flag[int]
	SBOMSources       *Flag[[]string]
	RekorURL          *Flag[string]
	DetectionPriority *Flag[string]
	DistroFlag        *Flag[string]
	SkipVersionCheck  *Flag[bool]
	DisableTelemetry  *Flag[bool]
}

type ScanOptions struct {
	Target            string
	SkipDirs          []string
	SkipFiles         []string
	OfflineScan       bool
	Scanners          types.Scanners
	FilePatterns      []string
	Parallel          int
	SBOMSources       []string
	RekorURL          string
	DetectionPriority ftypes.DetectionPriority
	Distro            ftypes.OS
	SkipVersionCheck  bool
	DisableTelemetry  bool
}

func NewScanFlagGroup() *ScanFlagGroup {
	return &ScanFlagGroup{
		SkipDirs:          SkipDirsFlag.Clone(),
		SkipFiles:         SkipFilesFlag.Clone(),
		OfflineScan:       OfflineScanFlag.Clone(),
		Scanners:          ScannersFlag.Clone(),
		FilePatterns:      FilePatternsFlag.Clone(),
		Parallel:          ParallelFlag.Clone(),
		SBOMSources:       SBOMSourcesFlag.Clone(),
		RekorURL:          RekorURLFlag.Clone(),
		Slow:              SlowFlag.Clone(),
		DetectionPriority: DetectionPriority.Clone(),
		DistroFlag:        DistroFlag.Clone(),
		SkipVersionCheck:  SkipVersionCheckFlag.Clone(),
		DisableTelemetry:  DisableTelemetryFlag.Clone(),
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
		f.DetectionPriority,
		f.DistroFlag,
		f.SkipVersionCheck,
		f.DisableTelemetry,
	}
}

func (f *ScanFlagGroup) ToOptions(opts *Options) error {
	var target string
	if len(opts.args) == 1 {
		target = opts.args[0]
	}

	parallel := f.Parallel.Value()
	if f.Parallel != nil && parallel == 0 {
		log.Info("Set '--parallel' to the number of CPUs", log.Int("parallel", runtime.NumCPU()))
		parallel = runtime.NumCPU()
	}

	var distro ftypes.OS
	if f.DistroFlag != nil && f.DistroFlag.Value() != "" {
		family, version, _ := strings.Cut(f.DistroFlag.Value(), "/")
		if !slices.Contains(ftypes.OSTypes, ftypes.OSType(family)) {
			return xerrors.Errorf("unknown OS family: %s, must be %q", family, ftypes.OSTypes)
		}
		distro = ftypes.OS{
			Family: ftypes.OSType(family),
			Name:   version,
		}
	}

	opts.ScanOptions = ScanOptions{
		Target:            target,
		SkipDirs:          f.SkipDirs.Value(),
		SkipFiles:         f.SkipFiles.Value(),
		OfflineScan:       f.OfflineScan.Value(),
		Scanners:          xstrings.ToTSlice[types.Scanner](f.Scanners.Value()),
		FilePatterns:      f.FilePatterns.Value(),
		Parallel:          parallel,
		SBOMSources:       f.SBOMSources.Value(),
		RekorURL:          f.RekorURL.Value(),
		DetectionPriority: ftypes.DetectionPriority(f.DetectionPriority.Value()),
		Distro:            distro,
		SkipVersionCheck:  f.SkipVersionCheck.Value(),
		DisableTelemetry:  f.DisableTelemetry.Value(),
	}
	return nil
}
