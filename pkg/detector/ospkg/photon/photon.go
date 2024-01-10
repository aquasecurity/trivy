package photon

import (
	"context"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/photon"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		"1.0": time.Date(2022, 2, 28, 23, 59, 59, 0, time.UTC),
		"2.0": time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC),
		// The following versions don't have the EOL dates yet.
		// See https://blogs.vmware.com/vsphere/2022/01/photon-1-x-end-of-support-announcement.html
		"3.0": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		"4.0": time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements the Photon scanner
type Scanner struct {
	vs photon.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: photon.NewVulnSrc(),
	}
}

// Detect scans and returns vulnerabilities using photon scanner
func (s *Scanner) Detect(osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Photon Linux vulnerabilities...")
	log.Logger.Debugf("Photon Linux: os version: %s", osVer)
	log.Logger.Debugf("Photon Linux: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Photon Linux advisory: %w", err)
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

// IsSupportedVersion checks if the version is supported.
func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	return osver.Supported(ctx, eolDates, osFamily, osVer)
}
