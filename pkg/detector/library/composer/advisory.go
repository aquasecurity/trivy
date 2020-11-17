package composer

import (
	"fmt"
	"strings"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
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
		var affectedVersions []string
		var patchedVersions []string
		for _, branch := range advisory.Branches {
			for _, version := range branch.Versions {
				if !strings.HasPrefix(version, "<=") && strings.HasPrefix(version, "<") {
					patchedVersions = append(patchedVersions, strings.Trim(version, "<"))
				}
			}
			affectedVersions = append(affectedVersions, strings.Join(branch.Versions, ", "))
		}

		adv := dbTypes.Advisory{VulnerableVersions: affectedVersions}
		if !s.comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     strings.Join(patchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}
