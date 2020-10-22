package cargo

import (
	"strings"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/xerrors"

	cargoSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/cargo"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Advisory encapsulates the cargo vulnerability scanner
type Advisory struct {
	vs cargoSrc.VulnSrc
}

// NewAdvisory is the factory method to return cargo Scanner
func NewAdvisory() *Advisory {
	return &Advisory{
		vs: cargoSrc.NewVulnSrc(),
	}
}

// DetectVulnerabilities scans and returns the cargo vulnerabilities
func (s *Advisory) DetectVulnerabilities(pkgName string, pkgVer *semver.Version) ([]types.DetectedVulnerability, error) {
	advisories, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get cargo advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		if utils.MatchVersions(pkgVer, advisory.PatchedVersions) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          strings.TrimSpace(pkgName),
			InstalledVersion: pkgVer.String(),
			FixedVersion:     strings.Join(advisory.PatchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}
