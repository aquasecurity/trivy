package chainguard

import (
	"context"

	version "github.com/knqyf263/go-apk-version"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/chainguard"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner implements the Chainguard scanner
type Scanner struct {
	vs chainguard.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: chainguard.NewVulnSrc(),
	}
}

// Detect vulnerabilities in package using Chainguard scanner
func (s *Scanner) Detect(_ string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Debug("Detecting Chainguard vulnerabilities...")

	log.Logger.Debugf("chainguard: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		srcName := pkg.SrcName
		if srcName == "" {
			srcName = pkg.Name
		}
		advisories, err := s.vs.Get("", srcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Chainguard advisories: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.Logger.Debugf("failed to parse Chainguard installed package version: %s", err)
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
		log.Logger.Debugf("failed to parse Chainguard fixed version: %s", err)
		return false
	}

	// It means the fixed vulnerability
	return installedVersion.LessThan(fixedVersion)
}

// IsSupportedVersion checks if the version is supported.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	// Chainguard doesn't have versions, so there is no case where a given input yields a
	// result of an unsupported Chainguard version.

	return true
}
