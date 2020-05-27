package ghsa

import (
	"os"
	"strings"

	"github.com/knqyf263/go-version"
	"golang.org/x/xerrors"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	scannerType = "ghsa"
)

type VulnSrc interface {
	Get(pkgName string) ([]ghsa.Advisory, error)
}

type Scanner struct {
	vs VulnSrc
}

func NewScanner(ecosystem ghsa.Ecosystem) *Scanner {
	return &Scanner{
		vs: ghsa.NewVulnSrc(ecosystem),
	}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error) {
	ghsas, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", s.Type(), err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range ghsas {
		if !utils.MatchVersions(pkgVer, advisory.VulnerableVersions) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer.String(),
			FixedVersion:     strings.Join(advisory.PatchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

func (s *Scanner) Type() string {
	return scannerType
}

func (s *Scanner) ParseLockfile(f *os.File) ([]ptypes.Library, error) {
	return nil, xerrors.New("unsupport parse lockfile")
}
