package npm

import (
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/node"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Advisory encapsulate Node vulnerability source
type Advisory struct {
	comparer Comparer
	vs       node.VulnSrc
}

// NewAdvisory is the factory method for Node Advisory
func NewAdvisory() *Advisory {
	return &Advisory{
		vs:       node.NewVulnSrc(),
		comparer: Comparer{},
	}
}

// DetectVulnerabilities scans and return vulnerability using Node package scanner
func (a *Advisory) DetectVulnerabilities(pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	advisories, err := a.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get node advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		if !a.comparer.IsVulnerable(pkgVer, advisory) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     createFixedVersions(advisory.PatchedVersions),
			DataSource:       advisory.DataSource,
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func createFixedVersions(patchedVersions []string) string {
	var fixedVersions []string
	for _, s := range patchedVersions {
		fixedVersions = append(fixedVersions, strings.TrimSpace(s))
	}
	return strings.Join(fixedVersions, ", ")
}
