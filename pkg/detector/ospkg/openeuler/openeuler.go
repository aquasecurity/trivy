package openeuler

import (
	"context"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	openeuler "github.com/aquasecurity/trivy-db/pkg/vulnsrc/openeuler"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	openeulerEOLDates = map[string]time.Time{
		// Source: https://www.openeuler.org/zh/other/lifecycle/
		"20.09":         time.Date(2021, 3, 31, 23, 59, 59, 0, time.UTC),
		"21.03":         time.Date(2021, 9, 30, 23, 59, 59, 0, time.UTC),
		"21.09":         time.Date(2022, 3, 31, 23, 59, 59, 0, time.UTC),
		"22.09":         time.Date(2023, 3, 31, 23, 59, 59, 0, time.UTC),
		"23.03":         time.Date(2023, 9, 30, 23, 59, 59, 0, time.UTC),
		"23.09":         time.Date(2024, 3, 31, 23, 59, 59, 0, time.UTC),
		"20.03-LTS":     time.Date(2022, 3, 31, 23, 59, 59, 0, time.UTC),
		"22.03-LTS":     time.Date(2024, 3, 31, 23, 59, 59, 0, time.UTC),
		"20.03-LTS-SP1": time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC),
		"20.03-LTS-SP2": time.Date(2022, 3, 31, 23, 59, 59, 0, time.UTC),
		"20.03-LTS-SP3": time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC),
		"20.03-LTS-SP4": time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC),
		"22.03-LTS-SP1": time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
		"22.03-LTS-SP2": time.Date(2024, 3, 31, 23, 59, 59, 0, time.UTC),
		"22.03-LTS-SP3": time.Date(2028, 3, 31, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements the openEuler scanner
type Scanner struct {
	vs openeuler.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: openeuler.NewVulnSrc(),
	}
}

// Detect scans and returns the vulnerabilities
func (s *Scanner) Detect(osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting openEuler vulnerabilities...")
	log.Logger.Debugf("openEuler: os version: %s", osVer)
	log.Logger.Debugf("openEuler: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.Name)
		if err != nil {
			return nil, xerrors.Errorf("failed to get openEuler advisory: %w", err)
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

// IsSupportedVersion checks if OSFamily can be scanned using openEuler scanner
func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	return osver.Supported(ctx, openeulerEOLDates, osFamily, osVer)
}
