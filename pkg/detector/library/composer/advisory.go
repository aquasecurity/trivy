package composer

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"

	"golang.org/x/xerrors"

	"github.com/Masterminds/semver/v3"

	composerSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/composer"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
)

type Advisory struct {
	vs composerSrc.VulnSrc
}

func NewAdvisory() *Advisory {
	return &Advisory{
		vs: composerSrc.NewVulnSrc(),
	}
}

func (s *Advisory) DetectVulnerabilities(pkgName string, pkgVer *semver.Version) ([]types.DetectedVulnerability, error) {
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

		if !utils.MatchVersions(pkgVer, affectedVersions) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer.String(),
			FixedVersion:     strings.Join(patchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}
