package nuget

import (
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy/pkg/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/knqyf263/go-version"
)

const (
	ScannerType = "nuget"
)

type Scanner struct {
	scannerType string
	vs          ghsa.VulnSrc
}

func NewScanner(scannerType string) *Scanner {
	return &Scanner{
		scannerType: scannerType,
		vs:          ghsa.NewVulnSrc(ghsa.Nuget),
	}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error) {
	var vulns []types.DetectedVulnerability
	ghsas, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", s.Type(), err)
	}

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

// TODO:
// func (s *Scanner) ParseLockfile(f *os.File) ([]ptypes.Library, error) {
// 	libs, err := nuget.Parse(f)
// 	if err != nil {
// 		return nil, xerrors.Errorf("invalid Nuget format: %w", err)
// 	}
// 	return libs, nil
// }

func (s *Scanner) Type() string {
	return s.scannerType
}
