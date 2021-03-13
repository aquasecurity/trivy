package debian

import (
	"strings"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	debianoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian-oval"

	version "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		"1.1": time.Date(1997, 6, 5, 23, 59, 59, 0, time.UTC),
		"1.2": time.Date(1998, 6, 5, 23, 59, 59, 0, time.UTC),
		"1.3": time.Date(1999, 3, 9, 23, 59, 59, 0, time.UTC),
		"2.0": time.Date(2000, 3, 9, 23, 59, 59, 0, time.UTC),
		"2.1": time.Date(2000, 10, 30, 23, 59, 59, 0, time.UTC),
		"2.2": time.Date(2003, 7, 30, 23, 59, 59, 0, time.UTC),
		"3.0": time.Date(2006, 6, 30, 23, 59, 59, 0, time.UTC),
		"3.1": time.Date(2008, 3, 30, 23, 59, 59, 0, time.UTC),
		"4.0": time.Date(2010, 2, 15, 23, 59, 59, 0, time.UTC),
		"5.0": time.Date(2012, 2, 6, 23, 59, 59, 0, time.UTC),
		// LTS
		"6.0": time.Date(2016, 2, 29, 23, 59, 59, 0, time.UTC),
		"7":   time.Date(2018, 5, 31, 23, 59, 59, 0, time.UTC),
		"8":   time.Date(2020, 6, 30, 23, 59, 59, 0, time.UTC),
		"9":   time.Date(2022, 6, 30, 23, 59, 59, 0, time.UTC),
		"10":  time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		"11":  time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
		"12":  time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements the Debian scanner
type Scanner struct {
	ovalVs dbTypes.VulnSrc
	vs     dbTypes.VulnSrc
}

// NewScanner is the factory method to return Scanner
func NewScanner() *Scanner {
	return &Scanner{
		ovalVs: debianoval.NewVulnSrc(),
		vs:     debian.NewVulnSrc(),
	}
}

// Detect scans and return vulnerabilities using Debian scanner
func (s *Scanner) Detect(osVer string, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Debian vulnerabilities...")

	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}
	log.Logger.Debugf("debian: os version: %s", osVer)
	log.Logger.Debugf("debian: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		// This bucket has only fixed vulnerabilities.
		// To detect vulnerabilities, it is necessary to compare versions between the installed version and the patched version.
		advisories, err := s.ovalVs.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get debian OVAL: %w", err)
		}

		installed := utils.FormatSrcVersion(pkg)
		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.Logger.Debugf("failed to parse Debian installed package version: %w", err)
			continue
		}

		for _, adv := range advisories {
			var fixedVersion version.Version
			fixedVersion, err = version.NewVersion(adv.FixedVersion)
			if err != nil {
				log.Logger.Debugf("failed to parse Debian package version: %w", err)
				continue
			}

			if installedVersion.LessThan(fixedVersion) {
				vuln := types.DetectedVulnerability{
					VulnerabilityID:  adv.VulnerabilityID,
					PkgName:          pkg.Name,
					InstalledVersion: installed,
					FixedVersion:     adv.FixedVersion,
					Layer:            pkg.Layer,
				}
				vulns = append(vulns, vuln)
			}
		}

		// This bucket has only unfixed vulnerabilities which don't have a patched version.
		// It is unnecessary to compare versions since it should be always vulnerable to an unfixed vulnerability.
		advisories, err = s.vs.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get debian advisory: %w", err)
		}
		for _, adv := range advisories {
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				Layer:            pkg.Layer,
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks is OSFamily can be scanned using Debian
func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	now := time.Now()
	return s.isSupportedVersion(now, osFamily, osVer)
}

func (s *Scanner) isSupportedVersion(now time.Time, osFamily, osVer string) bool {
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}

	eol, ok := eolDates[osVer]
	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}
	return now.Before(eol)
}
