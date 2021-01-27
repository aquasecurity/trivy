package redhat

import (
	"strings"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	redhatEOLDates = map[string]time.Time{
		"4": time.Date(2017, 5, 31, 23, 59, 59, 0, time.UTC),
		"5": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
		"6": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		// N/A
		"7": time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
		"8": time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
	}
	centosEOLDates = map[string]time.Time{
		"3": time.Date(2010, 10, 31, 23, 59, 59, 0, time.UTC),
		"4": time.Date(2012, 2, 29, 23, 59, 59, 0, time.UTC),
		"5": time.Date(2017, 3, 31, 23, 59, 59, 0, time.UTC),
		"6": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
		"7": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		"8": time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	excludedVendorsSuffix = []string{
		".remi",
	}
)

// Scanner implements the Redhat scanner
type Scanner struct {
	vs dbTypes.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: redhat.NewVulnSrc(),
	}
}

// Detect scans and returns redhat vulenrabilities
func (s *Scanner) Detect(osVer string, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting RHEL/CentOS vulnerabilities...")
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}
	log.Logger.Debugf("redhat: os version: %s", osVer)
	log.Logger.Debugf("redhat: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		if !s.isFromSupportedVendor(pkg) {
			log.Logger.Debugf("Skipping %s: unsupported vendor", pkg.Name)
			continue
		}

		// For Red Hat Security Data API containing only source package names
		pkgName := addModularNamespace(pkg.SrcName, pkg.Modularitylabel)
		advisories, err := s.vs.Get(osVer, pkgName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Red Hat advisories: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)

		for _, adv := range advisories {
			if adv.FixedVersion != "" {
				continue
			}
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				Layer:            pkg.Layer,
			}
			vulns = append(vulns, vuln)
		}

		// For Red Hat OVAL v2 containing only binary package names
		pkgName = addModularNamespace(pkg.Name, pkg.Modularitylabel)
		advisories, err = s.vs.Get(osVer, pkgName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Red Hat advisories: %w", err)
		}

		for _, adv := range advisories {
			fixedVersion := version.NewVersion(adv.FixedVersion)
			if installedVersion.LessThan(fixedVersion) {
				vuln := types.DetectedVulnerability{
					VulnerabilityID:  adv.VulnerabilityID,
					PkgName:          pkg.Name,
					InstalledVersion: installed,
					FixedVersion:     fixedVersion.String(),
					Layer:            pkg.Layer,
				}
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks is OSFamily can be scanned with Redhat scanner
func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	now := time.Now()
	return s.isSupportedVersion(now, osFamily, osVer)
}

func (s *Scanner) isSupportedVersion(now time.Time, osFamily, osVer string) bool {
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}

	var eolDate time.Time
	var ok bool
	if osFamily == os.RedHat {
		eolDate, ok = redhatEOLDates[osVer]
	} else if osFamily == os.CentOS {
		eolDate, ok = centosEOLDates[osVer]
	}
	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}
	return now.Before(eolDate)
}

func (s *Scanner) isFromSupportedVendor(pkg ftypes.Package) bool {
	for _, s := range excludedVendorsSuffix {
		if strings.HasSuffix(pkg.Release, s) {
			return false
		}
	}
	return true
}

func addModularNamespace(name, label string) string {
	// e.g. npm, nodejs:12:8030020201124152102:229f0a1c => nodejs:12::npm
	var count int
	for i, r := range label {
		if r == ':' {
			count++
		}
		if count == 2 {
			return label[:i] + "::" + name
		}
	}
	return name
}
