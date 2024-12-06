package oracle

import (
	"context"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	oracleoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/oracle-oval"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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
		"7": time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
		"8": time.Date(2029, 7, 18, 23, 59, 59, 0, time.UTC),
		"9": time.Date(2032, 7, 18, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements oracle vulnerability scanner
type Scanner struct {
	vs *oracleoval.VulnSrc
}

// NewScanner is the factory method to return oracle vulnerabilities
func NewScanner() *Scanner {
	return &Scanner{
		vs: oracleoval.NewVulnSrc(),
	}
}

// Detect scans and return vulnerability in Oracle scanner
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	osVer = osver.Major(osVer)
	log.InfoContext(ctx, "Detecting vulnerabilities...", log.String("os_version", osVer),
		log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.Name, pkg.Arch)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Oracle Linux advisory: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)
		for _, adv := range advisories {
			// We need to use only advisories from the same flavor as the package flavors.
			// See more in https://github.com/aquasecurity/trivy/issues/1967
			if oracleoval.PackageFlavor(adv.FixedVersion) != oracleoval.PackageFlavor(pkg.Release) {
				continue
			}

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

// IsSupportedVersion checks if the version is supported.
func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	return osver.Supported(ctx, eolDates, osFamily, osver.Major(osVer))
}
