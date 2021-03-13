package python

import (
	"strings"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/python"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Advisory encapsulates the python vulnerability scanner
type Advisory struct {
	vs       python.VulnSrc
	comparer comparer.Comparer
}

// NewAdvisory is the factory method to return Python Advisory
func NewAdvisory() *Advisory {
	return &Advisory{
		vs:       python.NewVulnSrc(),
		comparer: Pep440Comparer{},
	}
}

// DetectVulnerabilities scans and returns python vulnerabilities
func (s *Advisory) DetectVulnerabilities(pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	advisories, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get python advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		adv := dbTypes.Advisory{VulnerableVersions: advisory.Specs}
		if !s.comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     createFixedVersions(advisory.Specs),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func createFixedVersions(specs []string) string {
	var fixedVersions []string
	for _, spec := range specs {
		for _, s := range strings.Split(spec, ",") {
			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
				fixedVersions = append(fixedVersions, strings.TrimPrefix(s, "<"))
			}
		}
	}
	return strings.Join(fixedVersions, ", ")
}
