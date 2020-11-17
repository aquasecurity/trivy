package cargo

import (
	"strings"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	cargoSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/cargo"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Advisory encapsulates the cargo vulnerability scanner
type Advisory struct {
	vs       cargoSrc.VulnSrc
	comparer comparer.Comparer
}

// NewAdvisory is the factory method to return cargo Scanner
func NewAdvisory() *Advisory {
	return &Advisory{
		vs:       cargoSrc.NewVulnSrc(),
		comparer: comparer.GenericComparer{},
	}
}

// DetectVulnerabilities scans and returns the cargo vulnerabilities
func (s *Advisory) DetectVulnerabilities(pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	advisories, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get cargo advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		adv := dbTypes.Advisory{
			UnaffectedVersions: advisory.UnaffectedVersions,
			PatchedVersions:    advisory.PatchedVersions,
		}
		if len(adv.UnaffectedVersions) == 0 && len(adv.PatchedVersions) == 0 {
			// No patched version
			adv.VulnerableVersions = []string{">=0.0.0"}
		}

		if !s.comparer.IsVulnerable(pkgVer, adv) {
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
