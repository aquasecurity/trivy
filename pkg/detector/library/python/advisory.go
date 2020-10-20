package python

import (
	"strings"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/python"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Advisory encapsulates the python vulnerability scanner
type Advisory struct {
	vs python.VulnSrc
}

// NewAdvisory is the factory method to reutrn Python Advisory
func NewAdvisory() *Advisory {
	return &Advisory{
		vs: python.NewVulnSrc(),
	}
}

// DetectVulnerabilities scans and returns pythin vulnerabilities
func (s *Advisory) DetectVulnerabilities(pkgName string, pkgVer *semver.Version) ([]types.DetectedVulnerability, error) {
	advisories, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get python advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		if !utils.MatchVersions(pkgVer, advisory.Specs) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer.String(),
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
