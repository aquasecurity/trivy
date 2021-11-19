package osv

import (
	"strings"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
	"github.com/aquasecurity/trivy/pkg/types"
)

// VulnSrc defines the operations on vulnerability source
type VulnSrc interface {
	Get(pkgName string) ([]dbTypes.Advisory, error)
}

// Advisory implements VulnSrc
type Advisory struct {
	vs       VulnSrc
	comparer comparer.Comparer
}

// NewAdvisory is the factory method to return advisory
func NewAdvisory(ecosystemName string, comparer comparer.Comparer) *Advisory {
	return &Advisory{
		vs:       osv.NewVulnSrc(ecosystemName),
		comparer: comparer,
	}
}

// DetectVulnerabilities scans package for vulnerabilities
func (s *Advisory) DetectVulnerabilities(pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	advisories, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get osv advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		adv := dbTypes.Advisory{VulnerableVersions: advisory.VulnerableVersions}
		if !s.comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     strings.Join(advisory.PatchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}
