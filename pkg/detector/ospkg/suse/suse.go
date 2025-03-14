package suse

import (
	"context"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	susecvrf "github.com/aquasecurity/trivy-db/pkg/vulnsrc/suse-cvrf"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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
		"15.3": time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC),
		"15.4": time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
		"15.5": time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
		"15.6": time.Date(2031, 7, 31, 23, 59, 59, 0, time.UTC),
		// 6 months after SLES 15 SP7 release
		// "15.7": time.Date(2031, 7, 31, 23, 59, 59, 0, time.UTC),
	}
	slemicroEolDates = map[string]time.Time{
		// Source: https://www.suse.com/lifecycle/
		"5.0": time.Date(2022, 3, 31, 23, 59, 59, 0, time.UTC),
		"5.1": time.Date(2025, 10, 31, 23, 59, 59, 0, time.UTC),
		"5.2": time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC),
		"5.3": time.Date(2026, 10, 30, 23, 59, 59, 0, time.UTC),
		"5.4": time.Date(2027, 4, 30, 23, 59, 59, 0, time.UTC),
		"5.5": time.Date(2027, 10, 31, 23, 59, 59, 0, time.UTC),
		"6.0": time.Date(2028, 6, 30, 23, 59, 59, 0, time.UTC),
		// 6.1 will be released late 2024
		// "6.1": time.Date(2028, 11, 30, 23, 59, 59, 0, time.UTC),
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
		"15.4": time.Date(2023, 11, 30, 23, 59, 59, 0, time.UTC),
		"15.5": time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
		"15.6": time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
	}
)

// Type defines SUSE type
type Type int

const (
	// SUSEEnterpriseLinux is Linux Enterprise version
	SUSEEnterpriseLinux Type = iota
	// SUSE Linux Enterprise Micro is the micro series
	SUSEEnterpriseLinuxMicro
	// OpenSUSE for open versions
	OpenSUSE
	OpenSUSETumbleweed
)

// Scanner implements the SUSE scanner
type Scanner struct {
	vs susecvrf.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner(t Type) *Scanner {
	switch t {
	case SUSEEnterpriseLinux:
		return &Scanner{
			vs: susecvrf.NewVulnSrc(susecvrf.SUSEEnterpriseLinux),
		}
	case SUSEEnterpriseLinuxMicro:
		return &Scanner{
			vs: susecvrf.NewVulnSrc(susecvrf.SUSEEnterpriseLinuxMicro),
		}
	case OpenSUSE:
		return &Scanner{
			vs: susecvrf.NewVulnSrc(susecvrf.OpenSUSE),
		}
	case OpenSUSETumbleweed:
		return &Scanner{
			vs: susecvrf.NewVulnSrc(susecvrf.OpenSUSETumbleweed),
		}
	}
	return nil
}

// Detect scans and returns the vulnerabilities
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting vulnerabilities...", log.String("os_version", osVer),
		log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.Name)
		if err != nil {
			return nil, xerrors.Errorf("failed to get SUSE advisory: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)
		for _, adv := range advisories {
			fixedVersion := version.NewVersion(adv.FixedVersion)
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				PkgIdentifier:    pkg.Identifier,
				Layer:            pkg.Layer,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
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
func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	if osFamily == ftypes.SLES {
		return osver.Supported(ctx, slesEolDates, osFamily, osVer)
	}
	if osFamily == ftypes.SLEMicro {
		return osver.Supported(ctx, slemicroEolDates, osFamily, osVer)
	}
	// tumbleweed is a rolling release, it has no version and no eol
	if osFamily == ftypes.OpenSUSETumbleweed {
		return true
	}
	return osver.Supported(ctx, opensuseEolDates, osFamily, osVer)
}
