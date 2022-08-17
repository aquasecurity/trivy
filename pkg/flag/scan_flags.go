package flag

import (
	"fmt"
	"strings"

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
		Value:      fmt.Sprintf("%s,%s", types.SecurityCheckVulnerability, types.SecurityCheckSecret),
		Usage:      "comma-separated list of what security issues to detect (vuln,config,secret)",
	}
	SbomAttestationFlag = Flag{
		Name:       "sbom-attestation",
		ConfigName: "scan.sbom-attestation",
		Value:      false,
		Usage:      "try to use an SBOM attestation from OCI registry or rekor", // TODO: OCI registry? OCI registry attestation tag?
	}
)

type ScanFlagGroup struct {
	SkipDirs        *Flag
	SkipFiles       *Flag
	OfflineScan     *Flag
	SecurityChecks  *Flag
	SbomAttestation *Flag
}

type ScanOptions struct {
	Target          string
	SkipDirs        []string
	SkipFiles       []string
	OfflineScan     bool
	SecurityChecks  []string
	SbomAttestation bool
}

func NewScanFlagGroup() *ScanFlagGroup {
	return &ScanFlagGroup{
		SkipDirs:        &SkipDirsFlag,
		SkipFiles:       &SkipFilesFlag,
		OfflineScan:     &OfflineScanFlag,
		SecurityChecks:  &SecurityChecksFlag,
		SbomAttestation: &SbomAttestationFlag,
	}
}

func (f *ScanFlagGroup) Name() string {
	return "Scan"
}

func (f *ScanFlagGroup) Flags() []*Flag {
	return []*Flag{f.SkipDirs, f.SkipFiles, f.OfflineScan, f.SecurityChecks, f.SbomAttestation}
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

	return ScanOptions{
		Target:          target,
		SkipDirs:        getStringSlice(f.SkipDirs),
		SkipFiles:       getStringSlice(f.SkipFiles),
		OfflineScan:     getBool(f.OfflineScan),
		SecurityChecks:  securityChecks,
		SbomAttestation: getBool(f.SbomAttestation),
	}, nil
}

func parseSecurityCheck(securityCheck []string) ([]string, error) {
	switch {
	case len(securityCheck) == 0: // no checks. Can be empty when generating SBOM
		return nil, nil
	case len(securityCheck) == 1 && strings.Contains(securityCheck[0], ","): // get checks from flag
		securityCheck = strings.Split(securityCheck[0], ",")
	}

	var securityChecks []string
	for _, v := range securityCheck {
		if !slices.Contains(types.SecurityChecks, v) {
			return nil, xerrors.Errorf("unknown security check: %s", v)
		}
		securityChecks = append(securityChecks, v)
	}
	return securityChecks, nil
}
