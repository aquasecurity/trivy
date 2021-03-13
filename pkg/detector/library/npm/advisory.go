package npm

import (
	"strings"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
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
		adv := convertToGenericAdvisory(advisory)
		if !a.comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     createFixedVersions(advisory.PatchedVersions),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func convertToGenericAdvisory(advisory node.Advisory) dbTypes.Advisory {
	var vulnerable, patched []string
	if advisory.VulnerableVersions != "" {
		vulnerable = strings.Split(advisory.VulnerableVersions, "||")
	}
	if advisory.PatchedVersions != "" {
		patched = strings.Split(advisory.PatchedVersions, "||")
	}

	return dbTypes.Advisory{
		VulnerableVersions: vulnerable,
		PatchedVersions:    patched,
	}
}

func createFixedVersions(patchedVersions string) string {
	var fixedVersions []string
	for _, s := range strings.Split(patchedVersions, "||") {
		fixedVersions = append(fixedVersions, strings.TrimSpace(s))
	}
	return strings.Join(fixedVersions, ", ")
}
