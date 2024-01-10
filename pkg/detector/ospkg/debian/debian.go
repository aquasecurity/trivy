package debian

import (
	"context"
	"time"

	version "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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
		"11":  time.Date(2026, 8, 14, 23, 59, 59, 0, time.UTC),
		"12":  time.Date(2028, 6, 10, 23, 59, 59, 0, time.UTC),
		"13":  time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements the Debian scanner
type Scanner struct {
	vs debian.VulnSrc
}

// NewScanner is the factory method to return Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: debian.NewVulnSrc(),
	}
}

// Detect scans and return vulnerabilities using Debian scanner
func (s *Scanner) Detect(osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Debian vulnerabilities...")

	osVer = osver.Major(osVer)
	log.Logger.Debugf("debian: os version: %s", osVer)
	log.Logger.Debugf("debian: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		sourceVersion, err := version.NewVersion(utils.FormatSrcVersion(pkg))
		if err != nil {
			log.Logger.Debugf("Debian installed package version error: %s", err)
			continue
		}

		advisories, err := s.vs.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get debian advisories: %w", err)
		}

		for _, adv := range advisories {
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				VendorIDs:        adv.VendorIDs,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: utils.FormatVersion(pkg),
				FixedVersion:     adv.FixedVersion,
				PkgIdentifier:    pkg.Identifier,
				Status:           adv.Status,
				Layer:            pkg.Layer,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			}

			if adv.Severity != dbTypes.SeverityUnknown {
				// Package-specific severity
				vuln.SeveritySource = vulnerability.Debian
				vuln.Vulnerability = dbTypes.Vulnerability{
					Severity: adv.Severity.String(),
				}
			}

			// It means unfixed vulnerability. We don't have to compare versions.
			if adv.FixedVersion == "" {
				vulns = append(vulns, vuln)
				continue
			}

			var fixedVersion version.Version
			fixedVersion, err = version.NewVersion(adv.FixedVersion)
			if err != nil {
				log.Logger.Debugf("Debian advisory package version error: %s", err)
				continue
			}

			if sourceVersion.LessThan(fixedVersion) {
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks if the version is supported.
func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	return osver.Supported(ctx, eolDates, osFamily, osver.Major(osVer))
}
