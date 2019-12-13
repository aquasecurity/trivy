package oracle

import (
	"strings"
	"time"

	oracleoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/oracle-oval"
	version "github.com/knqyf263/go-rpm-version"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"

	"k8s.io/utils/clock"
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

type Scanner struct {
	vs    dbTypes.VulnSrc
	clock clock.Clock
}

func NewScanner() *Scanner {
	return &Scanner{
		vs:    oracleoval.NewVulnSrc(),
		clock: clock.RealClock{},
	}
}

func (s *Scanner) Detect(osVer string, pkgs []analyzer.Package) ([]types.DetectedVulnerability, error) {
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
			fixedVersion := version.NewVersion(adv.FixedVersion)
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
			}
			if installedVersion.LessThan(fixedVersion) {
				vuln.FixedVersion = adv.FixedVersion
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

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
