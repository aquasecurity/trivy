package flag

import (
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	SkipDirsFlag = Flag{
		Name:       "skip-dirs",
		ConfigName: "scan.skip-dirs",
		Value:      []string{},
		Usage:      "specify the directories where the traversal is skipped",
	}
	SkipFilesFlag = Flag{
		Name:       "skip-files",
		ConfigName: "scan.skip-files",
		Value:      []string{},
		Usage:      "specify the file paths to skip traversal",
	}
	OfflineScanFlag = Flag{
		Name:       "offline-scan",
		ConfigName: "scan.offline",
		Value:      false,
		Usage:      "do not issue API requests to identify dependencies",
	}
	ScannersFlag = Flag{
		Name:       "scanners",
		ConfigName: "scan.scanners",
		Value: types.Scanners{
			types.VulnerabilityScanner,
			types.SecretScanner,
		}.StringSlice(),
		Aliases: []Alias{
			{
				Name:       "security-checks",
				ConfigName: "scan.security-checks",
				Deprecated: true, // --security-checks was renamed to --scanners
			},
		},
		Usage: "comma-separated list of what security issues to detect (vuln,config,secret,license)",
	}
	FilePatternsFlag = Flag{
		Name:       "file-patterns",
		ConfigName: "scan.file-patterns",
		Value:      []string{},
		Usage:      "specify config file patterns",
	}
	SlowFlag = Flag{
		Name:       "slow",
		ConfigName: "scan.slow",
		Value:      false,
		Usage:      "scan over time with lower CPU and memory utilization",
	}
	SBOMSourcesFlag = Flag{
		Name:       "sbom-sources",
		ConfigName: "scan.sbom-sources",
		Value:      []string{},
		Usage:      "[EXPERIMENTAL] try to retrieve SBOM from the specified sources (oci,rekor)",
	}
	RekorURLFlag = Flag{
		Name:       "rekor-url",
		ConfigName: "scan.rekor-url",
		Value:      "https://rekor.sigstore.dev",
		Usage:      "[EXPERIMENTAL] address of rekor STL server",
	}
)

type ScanFlagGroup struct {
	SkipDirs     *Flag
	SkipFiles    *Flag
	OfflineScan  *Flag
	Scanners     *Flag
	FilePatterns *Flag
	Slow         *Flag
	SBOMSources  *Flag
	RekorURL     *Flag
}

type ScanOptions struct {
	Target       string
	SkipDirs     []string
	SkipFiles    []string
	OfflineScan  bool
	Scanners     types.Scanners
	FilePatterns []string
	Slow         bool
	SBOMSources  []string
	RekorURL     string
}

func NewScanFlagGroup() *ScanFlagGroup {
	return &ScanFlagGroup{
		SkipDirs:     &SkipDirsFlag,
		SkipFiles:    &SkipFilesFlag,
		OfflineScan:  &OfflineScanFlag,
		Scanners:     &ScannersFlag,
		FilePatterns: &FilePatternsFlag,
		Slow:         &SlowFlag,
		SBOMSources:  &SBOMSourcesFlag,
		RekorURL:     &RekorURLFlag,
	}
}

func (f *ScanFlagGroup) Name() string {
	return "Scan"
}

func (f *ScanFlagGroup) Flags() []*Flag {
	return []*Flag{
		f.SkipDirs,
		f.SkipFiles,
		f.OfflineScan,
		f.Scanners,
		f.FilePatterns,
		f.Slow,
		f.SBOMSources,
		f.RekorURL,
	}
}

func (f *ScanFlagGroup) ToOptions(args []string) (ScanOptions, error) {
	var target string
	if len(args) == 1 {
		target = args[0]
	}
	scanners, err := parseScanners(getStringSlice(f.Scanners), types.AllScanners)
	if err != nil {
		return ScanOptions{}, xerrors.Errorf("unable to parse scanners: %w", err)
	}

	sbomSources := getStringSlice(f.SBOMSources)
	if err = validateSBOMSources(sbomSources); err != nil {
		return ScanOptions{}, xerrors.Errorf("unable to parse SBOM sources: %w", err)
	}

	return ScanOptions{
		Target:       target,
		SkipDirs:     getStringSlice(f.SkipDirs),
		SkipFiles:    getStringSlice(f.SkipFiles),
		OfflineScan:  getBool(f.OfflineScan),
		Scanners:     scanners,
		FilePatterns: getStringSlice(f.FilePatterns),
		Slow:         getBool(f.Slow),
		SBOMSources:  sbomSources,
		RekorURL:     getString(f.RekorURL),
	}, nil
}

func parseScanners(scanner []string, allowedScanners []types.Scanner) (types.Scanners, error) {
	var scanners types.Scanners
	for _, v := range scanner {
		s := types.Scanner(v)
		if !slices.Contains(allowedScanners, s) {
			return nil, xerrors.Errorf("unknown scanner: %s", v)
		}
		scanners = append(scanners, s)
	}
	return scanners, nil
}

func validateSBOMSources(sbomSources []string) error {
	for _, v := range sbomSources {
		if !slices.Contains(types.SBOMSources, v) {
			return xerrors.Errorf("unknown SBOM source: %s", v)
		}
	}
	return nil
}
