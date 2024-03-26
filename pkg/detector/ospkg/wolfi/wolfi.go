package wolfi

import (
	"context"

	version "github.com/knqyf263/go-apk-version"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/wolfi"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner implements the Wolfi scanner
type Scanner struct {
	vs wolfi.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: wolfi.NewVulnSrc(),
	}
}

// Detect vulnerabilities in package using Wolfi scanner
func (s *Scanner) Detect(_ string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Debug("Detecting Wolfi vulnerabilities...")

	log.Logger.Debugf("wolfi: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		srcName := pkg.SrcName
		if srcName == "" {
			srcName = pkg.Name
		}
		advisories, err := s.vs.Get("", srcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Wolfi advisories: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.Logger.Debugf("failed to parse Wolfi Linux installed package version: %s", err)
			continue
		}

		for _, adv := range advisories {
			if !s.isVulnerable(installedVersion, adv) {
				continue
			}
			vulns = append(vulns, types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				FixedVersion:     adv.FixedVersion,
				Layer:            pkg.Layer,
				PkgIdentifier:    pkg.Identifier,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			})
		}
	}
	return vulns, nil
}

func (s *Scanner) isVulnerable(installedVersion version.Version, adv dbTypes.Advisory) bool {
	// Compare versions for fixed vulnerabilities
	fixedVersion, err := version.NewVersion(adv.FixedVersion)
	if err != nil {
		log.Logger.Debugf("failed to parse Wolfi Linux fixed version: %s", err)
		return false
	}

	// It means the fixed vulnerability
	return installedVersion.LessThan(fixedVersion)
}

// IsSupportedVersion checks if the version is supported.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	// Wolfi doesn't have versions, so there is no case where a given input yields a
	// result of an unsupported Wolfi version.

	return true
}
