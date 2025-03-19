package alma

import (
	"context"
	"strings"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alma"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		// Source:
		// https://endoflife.date/almalinux
		"8": time.Date(2029, 3, 1, 23, 59, 59, 0, time.UTC),
		"9": time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements the AlmaLinux scanner
type Scanner struct {
	vs *alma.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: alma.NewVulnSrc(),
	}
}

// Detect vulnerabilities in package using AlmaLinux scanner
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	osVer = osver.Major(osVer)
	log.InfoContext(ctx, "Detecting vulnerabilities...", log.String("os_version", osVer),
		log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	var skipPkgs []string
	for _, pkg := range pkgs {
		if strings.Contains(pkg.Release, ".module_el") && pkg.Modularitylabel == "" {
			skipPkgs = append(skipPkgs, pkg.Name)
			continue
		}
		pkgName := addModularNamespace(pkg.Name, pkg.Modularitylabel)
		advisories, err := s.vs.Get(osVer, pkgName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get AlmaLinux advisories: %w", err)
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
	if len(skipPkgs) > 0 {
		log.InfoContext(ctx, "Skipped detection of the packages because modular packages cannot be detected correctly due to a bug in AlmaLinux. See also: https://bugs.almalinux.org/view.php?id=173",
			log.Any("packages", skipPkgs))
	}

	return vulns, nil
}

// IsSupportedVersion checks if the version is supported.
func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	return osver.Supported(ctx, eolDates, osFamily, osver.Major(osVer))
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
