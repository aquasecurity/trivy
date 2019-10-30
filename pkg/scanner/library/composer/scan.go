package composer

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/composer"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	composerSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/composer"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/knqyf263/go-version"
)

const (
	scannerType = "composer"
)

type Scanner struct {
	vs composerSrc.VulnSrc
}

func NewScanner() *Scanner {
	return &Scanner{
		vs: composerSrc.NewVulnSrc(),
	}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error) {
	ref := fmt.Sprintf("composer://%s", pkgName)
	advisories, err := s.vs.Get(ref)
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", s.Type(), err)
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

func (s *Scanner) ParseLockfile(f *os.File) ([]ptypes.Library, error) {
	libs, err := composer.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid composer.lock format: %w", err)
	}
	return libs, nil
}
func (s *Scanner) Type() string {
	return scannerType
}
