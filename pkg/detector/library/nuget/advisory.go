package nuget

import (
	"github.com/Masterminds/semver/v3"
	ghsaSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
	"strings"
)

type Advisory struct {
	vs ghsaSrc.VulnSrc
}

func NewAdvisory() *Advisory {
	return &Advisory{
		vs: ghsaSrc.NewVulnSrc(ghsaSrc.Nuget),
	}
}

func (s *Advisory) DetectVulnerabilities(pkgName string, pkgVer *semver.Version) ([]types.DetectedVulnerability, error) {
	advisories, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get nuget advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		if utils.MatchVersions(pkgVer, advisory.PatchedVersions) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          strings.TrimSpace(pkgName),
			InstalledVersion: pkgVer.String(),
			FixedVersion:     strings.Join(advisory.PatchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}
