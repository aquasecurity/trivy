package composer

import (
	"fmt"
	"strings"

	"golang.org/x/xerrors"

	composerSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/composer"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Advisory encapsulates composer.VulnSrc
type Advisory struct {
	vs       composerSrc.VulnSrc
	comparer comparer.Comparer // TODO: implement a comparer for Composer
}

// NewAdvisory is the factory method of Advisory
func NewAdvisory() *Advisory {
	return &Advisory{
		vs:       composerSrc.NewVulnSrc(),
		comparer: comparer.GenericComparer{},
	}
}

// DetectVulnerabilities returns the vulnerabilities in a package
func (s *Advisory) DetectVulnerabilities(pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	ref := fmt.Sprintf("composer://%s", pkgName)
	advisories, err := s.vs.Get(ref)
	if err != nil {
		return nil, xerrors.Errorf("failed to get composer advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		var patchedVersions []string
		for _, vulnerableRange := range advisory.VulnerableVersions {
			// e.g. ">=5, <5.3.1"
			for _, v := range strings.Split(vulnerableRange, ", ") {
				// e.g. "<5.3.1"
				if !strings.HasPrefix(v, "<=") && strings.HasPrefix(v, "<") {
					patchedVersions = append(patchedVersions, strings.Trim(v, "<"))
				}
			}
		}

		if !s.comparer.IsVulnerable(pkgVer, advisory) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     strings.Join(patchedVersions, ", "),
			DataSource:       advisory.DataSource,
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}
