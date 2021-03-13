package bundler

import (
	"strings"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	bundlerSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/bundler"
	"github.com/aquasecurity/trivy/pkg/types"
)

// VulnSrc defines the operation on bundler vulnerability
type VulnSrc interface {
	Get(pkgName string) ([]bundlerSrc.Advisory, error)
}

// Advisory implements the bundler VulnSrc
type Advisory struct {
	comparer RubyGemsComparer
	vs       VulnSrc
}

// NewAdvisory is the factory method to return bundler.Advisory
func NewAdvisory() *Advisory {
	return &Advisory{
		vs:       bundlerSrc.NewVulnSrc(),
		comparer: RubyGemsComparer{},
	}
}

// DetectVulnerabilities scans and returns Vulnerability in bundler
func (a *Advisory) DetectVulnerabilities(pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	advisories, err := a.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get bundler advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		adv := dbTypes.Advisory{
			UnaffectedVersions: advisory.UnaffectedVersions,
			PatchedVersions:    advisory.PatchedVersions,
		}
		if !a.comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          strings.TrimSpace(pkgName),
			InstalledVersion: pkgVer,
			FixedVersion:     strings.Join(advisory.PatchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}
