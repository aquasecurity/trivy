package ghsa

import (
	"strings"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// VulnSrc defines the operations on vulnerability source
type VulnSrc interface {
	Get(pkgName string) ([]ghsa.Advisory, error)
}

// Advisory implements VulnSrc
type Advisory struct {
	vs VulnSrc
}

// NewAdvisory is the factory method to return advisory
func NewAdvisory(ecosystem ghsa.Ecosystem) *Advisory {
	return &Advisory{
		vs: ghsa.NewVulnSrc(ecosystem),
	}
}

// DetectVulnerabilities scans package for vulnerabilities
func (s *Advisory) DetectVulnerabilities(pkgName string, pkgVer *semver.Version) ([]types.DetectedVulnerability, error) {
	advisories, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get ghsa advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		if !utils.MatchVersions(pkgVer, advisory.VulnerableVersions) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer.String(),
			FixedVersion:     strings.Join(advisory.PatchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}
