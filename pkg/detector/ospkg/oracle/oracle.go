package oracle

import (
	"strings"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	oracleoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/oracle-oval"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		// Source:
		// https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf
		// https://community.oracle.com/docs/DOC-917964
		"3": time.Date(2011, 12, 31, 23, 59, 59, 0, time.UTC),
		"4": time.Date(2013, 12, 31, 23, 59, 59, 0, time.UTC),
		"5": time.Date(2017, 12, 31, 23, 59, 59, 0, time.UTC),
		"6": time.Date(2021, 3, 21, 23, 59, 59, 0, time.UTC),
		"7": time.Date(2024, 7, 23, 23, 59, 59, 0, time.UTC),
		"8": time.Date(2029, 7, 18, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements oracle vulnerability scanner
type Scanner struct {
	vs    dbTypes.VulnSrc
	clock clock.Clock
}

// NewScanner is the factory method to return oracle vulnerabilities
func NewScanner() *Scanner {
	return &Scanner{
		vs:    oracleoval.NewVulnSrc(),
		clock: clock.RealClock{},
	}
}

// Detect scans and return vulnerability in Oracle scanner
func (s *Scanner) Detect(osVer string, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Oracle Linux vulnerabilities...")

	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}

	log.Logger.Debugf("Oracle Linux: os version: %s", osVer)
	log.Logger.Debugf("Oracle Linux: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Oracle Linux advisory: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)
		for _, adv := range advisories {
			// Skip if only one of them contains .ksplice1.
			if strings.Contains(adv.FixedVersion, ".ksplice1.") != strings.Contains(pkg.Release, ".ksplice1.") {
				continue
			}
			fixedVersion := version.NewVersion(adv.FixedVersion)
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				Layer:            pkg.Layer,
			}
			if installedVersion.LessThan(fixedVersion) {
				vuln.FixedVersion = adv.FixedVersion
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks is OSFamily can be scanned with Oracle scanner
func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}

	eol, ok := eolDates[osVer]
	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}

	return s.clock.Now().Before(eol)
}
