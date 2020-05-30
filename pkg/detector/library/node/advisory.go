package node

import (
	"strings"

	version "github.com/knqyf263/go-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/node"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Advisory struct {
	vs node.VulnSrc
}

func NewAdvisory() *Advisory {
	return &Advisory{
		vs: node.NewVulnSrc(),
	}
}

func (s *Advisory) DetectVulnerabilities(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error) {
	replacer := strings.NewReplacer(".alpha", "-alpha", ".beta", "-beta", ".rc", "-rc", " <", ", <", " >", ", >")
	advisories, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get node advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		// e.g. <= 2.15.0 || >= 3.0.0 <= 3.8.2
		//  => {"<=2.15.0", ">= 3.0.0, <= 3.8.2"}
		var vulnerableVersions []string
		for _, version := range strings.Split(advisory.VulnerableVersions, " || ") {
			version = strings.TrimSpace(version)
			vulnerableVersions = append(vulnerableVersions, replacer.Replace(version))
		}

		if !utils.MatchVersions(pkgVer, vulnerableVersions) {
			continue
		}

		var patchedVersions []string
		for _, version := range strings.Split(advisory.PatchedVersions, " || ") {
			version = strings.TrimSpace(version)
			patchedVersions = append(patchedVersions, replacer.Replace(version))
		}

		if utils.MatchVersions(pkgVer, patchedVersions) {
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
