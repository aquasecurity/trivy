package bundler

import (
	"strings"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/xerrors"

	bundlerSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/bundler"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// VulnSrc defines the operation on bundler vulnerability
type VulnSrc interface {
	Get(pkgName string) ([]bundlerSrc.Advisory, error)
}

// Advisory implements the bundler VulnSrc
type Advisory struct {
	vs VulnSrc
}

// NewAdvisory is the factory method to return bundler.Advisory
func NewAdvisory() *Advisory {
	return &Advisory{
		vs: bundlerSrc.NewVulnSrc(),
	}
}

// DetectVulnerabilities scans and returns Vulnerability in bundler
func (a *Advisory) DetectVulnerabilities(pkgName string, pkgVer *semver.Version) ([]types.DetectedVulnerability, error) {
	advisories, err := a.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get bundler advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		if utils.MatchVersions(pkgVer, advisory.PatchedVersions) {
			continue
		}
		if utils.MatchVersions(pkgVer, advisory.UnaffectedVersions) {
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
