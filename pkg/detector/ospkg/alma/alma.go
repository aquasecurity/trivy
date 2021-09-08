package alma

import (
	"strings"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alma"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		// Source:
		// https://wiki.almalinux.org/FAQ.html#how-long-will-cloudlinux-support-almalinux
		"8": time.Date(2029, 12, 31, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements the AlmaLinux scanner
type Scanner struct {
	vs alma.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: alma.NewVulnSrc(),
	}
}

// Detect vulnerabilities in package using AlmaLinux scanner
func (s *Scanner) Detect(osVer string, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting AlmaLinux vulnerabilities...")

	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}

	log.Logger.Debugf("AlmaLinux: os version: %s", osVer)
	log.Logger.Debugf("AlmaLinux: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)

		pkgName := addModularNamespace(pkg.SrcName, pkg.Modularitylabel)
		advisories, err := s.vs.Get(osVer, pkgName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get AlmaLinux advisory: %w", err)
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

		pkgName = addModularNamespace(pkg.Name, pkg.Modularitylabel)
		advisories, err = s.vs.Get(osVer, pkgName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get AlmaLinux advisory: %w", err)
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

// IsSupportedVersion checks the OSFamily can be scanned using Alpine scanner
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
