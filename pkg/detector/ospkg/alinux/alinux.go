package alinux

import (
	"context"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbAlinux "github.com/aquasecurity/trivy-db/pkg/vulnsrc/alinux"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		// https://www.alibabacloud.com/help/en/alinux/product-overview/alibaba-cloud-linux-overview
		"2": time.Date(2024, 3, 31, 23, 59, 59, 0, time.UTC),
		"3": time.Date(2031, 4, 30, 23, 59, 59, 0, time.UTC),
		"4": time.Date(2038, 6, 30, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements the Alibaba Cloud Linux scanner
type Scanner struct {
	vs dbAlinux.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: dbAlinux.NewVulnSrc(),
	}
}

// Detect vulnerabilities in packages using the Alinux scanner
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	osVer = osver.Major(osVer)
	log.InfoContext(ctx, "Detecting vulnerabilities...", log.String("os_version", osVer),
		log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(db.GetParams{
			Release: osVer,
			PkgName: pkg.Name,
		})
		if err != nil {
			return nil, xerrors.Errorf("failed to get Alinux advisories: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)
		for _, adv := range advisories {
			fixedVersion := version.NewVersion(adv.FixedVersion)
			if installedVersion.LessThan(fixedVersion) {
				vuln := types.DetectedVulnerability{
					VulnerabilityID:  adv.VulnerabilityID,
					PkgID:            pkg.ID,
					PkgName:          pkg.Name,
					InstalledVersion: installed,
					FixedVersion:     fixedVersion.String(),
					PkgIdentifier:    pkg.Identifier,
					Layer:            pkg.Layer,
					DataSource:       adv.DataSource,
					Custom:           adv.Custom,
				}
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
