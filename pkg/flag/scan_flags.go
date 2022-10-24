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
	SecurityChecksFlag = Flag{
		Name:       "security-checks",
		ConfigName: "scan.security-checks",
		Value:      []string{types.SecurityCheckVulnerability, types.SecurityCheckSecret},
		Usage:      "comma-separated list of what security issues to detect (vuln,config,secret,license)",
	}
	ComplianceFlag = Flag{
		Name:       "compliance",
		ConfigName: "scan.compliance",
		Value:      "",
		Usage:      "comma-separated list of what compliance reports to generate (nsa)",
	}
	FilePatternsFlag = Flag{
		Name:       "file-patterns",
		ConfigName: "scan.file-patterns",
		Value:      []string{},
		Usage:      "specify config file patterns",
	}
	SBOMSourcesFlag = Flag{
		Name:       "sbom-sources",
		ConfigName: "scan.sbom-sources",
		Value:      []string{},
		Usage:      "[EXPERIMENTAL] try to retrieve SBOM from the specified sources (rekor)",
	}
	RekorURLFlag = Flag{
		Name:       "rekor-url",
		ConfigName: "scan.rekor-url",
		Value:      "https://rekor.sigstore.dev",
		Usage:      "[EXPERIMENTAL] address of rekor STL server",
	}
)

type ScanFlagGroup struct {
	SkipDirs       *Flag
	SkipFiles      *Flag
	OfflineScan    *Flag
	SecurityChecks *Flag
	Compliance     *Flag
	FilePatterns   *Flag
	SBOMSources    *Flag
	RekorURL       *Flag
}

type ScanOptions struct {
	Target         string
	SkipDirs       []string
	SkipFiles      []string
	OfflineScan    bool
	SecurityChecks []string
	Compliance     string
	FilePatterns   []string
	SBOMSources    []string
	RekorURL       string
}

func NewScanFlagGroup() *ScanFlagGroup {
	return &ScanFlagGroup{
		SkipDirs:       &SkipDirsFlag,
		SkipFiles:      &SkipFilesFlag,
		OfflineScan:    &OfflineScanFlag,
		SecurityChecks: &SecurityChecksFlag,
		Compliance:     &ComplianceFlag,
		FilePatterns:   &FilePatternsFlag,
		SBOMSources:    &SBOMSourcesFlag,
		RekorURL:       &RekorURLFlag,
	}
}

func (f *ScanFlagGroup) Name() string {
	return "Scan"
}

func (f *ScanFlagGroup) Flags() []*Flag {
	return []*Flag{f.SkipDirs, f.SkipFiles, f.OfflineScan, f.SecurityChecks, f.Compliance, f.FilePatterns, f.SBOMSources, f.RekorURL}
}

func (f *ScanFlagGroup) ToOptions(args []string) (ScanOptions, error) {
	var target string
	if len(args) == 1 {
		target = args[0]
	}
	securityChecks, err := parseSecurityCheck(getStringSlice(f.SecurityChecks))
	if err != nil {
		return ScanOptions{}, xerrors.Errorf("unable to parse security checks: %w", err)
	}
	complianceTypes, err := parseComplianceTypes(getString(f.Compliance))
	if err != nil {
		return ScanOptions{}, xerrors.Errorf("unable to parse compliance types: %w", err)
	}

	sbomSources := getStringSlice(f.SBOMSources)
	if err = validateSBOMSources(sbomSources); err != nil {
		return ScanOptions{}, xerrors.Errorf("unable to parse SBOM sources: %w", err)
	}

	return ScanOptions{
		Target:         target,
		SkipDirs:       getStringSlice(f.SkipDirs),
		SkipFiles:      getStringSlice(f.SkipFiles),
		OfflineScan:    getBool(f.OfflineScan),
		SecurityChecks: securityChecks,
		Compliance:     complianceTypes,
		FilePatterns:   getStringSlice(f.FilePatterns),
		SBOMSources:    sbomSources,
		RekorURL:       getString(f.RekorURL),
	}, nil
}

func parseSecurityCheck(securityCheck []string) ([]string, error) {
	var securityChecks []string
	for _, v := range securityCheck {
		if !slices.Contains(types.SecurityChecks, v) {
			return nil, xerrors.Errorf("unknown security check: %s", v)
		}
		securityChecks = append(securityChecks, v)
	}
	return securityChecks, nil
}

func parseComplianceTypes(compliance interface{}) (string, error) {
	complianceString, ok := compliance.(string)
	if !ok || (len(complianceString) > 0 && !slices.Contains(types.Compliances, complianceString)) {
		return "", xerrors.Errorf("unknown compliance : %v", compliance)
	}
	return complianceString, nil
}

func validateSBOMSources(sbomSources []string) error {
	for _, v := range sbomSources {
		if !slices.Contains(types.SBOMSources, v) {
			return xerrors.Errorf("unknown SBOM source: %s", v)
		}
	}
	return nil
}
