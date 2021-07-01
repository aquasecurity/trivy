package suse

import (
	"time"

	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	version "github.com/knqyf263/go-rpm-version"

	fos "github.com/aquasecurity/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	susecvrf "github.com/aquasecurity/trivy-db/pkg/vulnsrc/suse-cvrf"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	slesEolDates = map[string]time.Time{
		// Source: https://www.suse.com/lifecycle/
		"10":   time.Date(2007, 12, 31, 23, 59, 59, 0, time.UTC),
		"10.1": time.Date(2008, 11, 30, 23, 59, 59, 0, time.UTC),
		"10.2": time.Date(2010, 4, 11, 23, 59, 59, 0, time.UTC),
		"10.3": time.Date(2011, 10, 11, 23, 59, 59, 0, time.UTC),
		"10.4": time.Date(2013, 7, 31, 23, 59, 59, 0, time.UTC),
		"11":   time.Date(2010, 12, 31, 23, 59, 59, 0, time.UTC),
		"11.1": time.Date(2012, 8, 31, 23, 59, 59, 0, time.UTC),
		"11.2": time.Date(2014, 1, 31, 23, 59, 59, 0, time.UTC),
		"11.3": time.Date(2016, 1, 31, 23, 59, 59, 0, time.UTC),
		"11.4": time.Date(2019, 3, 31, 23, 59, 59, 0, time.UTC),
		"12":   time.Date(2016, 6, 30, 23, 59, 59, 0, time.UTC),
		"12.1": time.Date(2017, 5, 31, 23, 59, 59, 0, time.UTC),
		"12.2": time.Date(2018, 3, 31, 23, 59, 59, 0, time.UTC),
		"12.3": time.Date(2019, 1, 30, 23, 59, 59, 0, time.UTC),
		"12.4": time.Date(2020, 6, 30, 23, 59, 59, 0, time.UTC),
		"12.5": time.Date(2024, 10, 31, 23, 59, 59, 0, time.UTC),
		"15":   time.Date(2019, 12, 31, 23, 59, 59, 0, time.UTC),
		"15.1": time.Date(2021, 1, 31, 23, 59, 59, 0, time.UTC),
		"15.2": time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC),
		// 6 months after SLES 15 SP4 release
		"15.3": time.Date(2028, 7, 31, 23, 59, 59, 0, time.UTC),
		// 6 months after SLES 15 SP5 release
		// "15.4":   time.Date(2028, 7, 31, 23, 59, 59, 0, time.UTC),
	}

	opensuseEolDates = map[string]time.Time{
		// Source: https://en.opensuse.org/Lifetime
		"42.1": time.Date(2017, 5, 17, 23, 59, 59, 0, time.UTC),
		"42.2": time.Date(2018, 1, 26, 23, 59, 59, 0, time.UTC),
		"42.3": time.Date(2019, 6, 30, 23, 59, 59, 0, time.UTC),
		"15.0": time.Date(2019, 12, 3, 23, 59, 59, 0, time.UTC),
		"15.1": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
		"15.2": time.Date(2021, 11, 30, 23, 59, 59, 0, time.UTC),
		"15.3": time.Date(2022, 11, 30, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements suse scanner
type Scanner struct {
	vs    dbTypes.VulnSrc
	clock clock.Clock
}

// Type to define SUSE type
type Type int

const (
	// SUSEEnterpriseLinux is Linux Enterprise version
	SUSEEnterpriseLinux Type = iota
	// OpenSUSE for open versions
	OpenSUSE
)

// NewScanner is the factory method for Scanner
func NewScanner(t Type) *Scanner {
	switch t {
	case SUSEEnterpriseLinux:
		return &Scanner{
			vs:    susecvrf.NewVulnSrc(susecvrf.SUSEEnterpriseLinux),
			clock: clock.RealClock{},
		}
	case OpenSUSE:
		return &Scanner{
			vs:    susecvrf.NewVulnSrc(susecvrf.OpenSUSE),
			clock: clock.RealClock{},
		}
	}
	return nil
}

// Detect scans and returns the vulnerabilities
func (s *Scanner) Detect(osVer string, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting SUSE vulnerabilities...")
	log.Logger.Debugf("SUSE: os version: %s", osVer)
	log.Logger.Debugf("SUSE: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get SUSE advisory: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)
		for _, adv := range advisories {
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

// IsSupportedVersion checks if OSFamily can be scanned using SUSE scanner
func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	var eolDate time.Time
	var ok bool

	if osFamily == fos.SLES {
		eolDate, ok = slesEolDates[osVer]
	} else if osFamily == fos.OpenSUSELeap {
		eolDate, ok = opensuseEolDates[osVer]
	}

	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}

	return s.clock.Now().Before(eolDate)
}
