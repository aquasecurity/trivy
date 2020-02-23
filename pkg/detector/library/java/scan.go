package java

import (
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy/pkg/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/knqyf263/go-version"
)

const (
	ScannerTypeMaven  = "maven"
	ScannerTypeGradle = "gradle"
)

type Scanner struct {
	scannerType string
	vs          ghsa.VulnSrc
}

func NewScanner(scannerType string) *Scanner {
	return &Scanner{
		scannerType: scannerType,
		vs:          ghsa.NewVulnSrc(ghsa.Maven),
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
// 	if s.Type() == ScannerTypeMaven {
// 		return s.parseMaven(f)
// 	}
// 	return s.parseGradle(f)
// }
//
// func (s *Scanner) parseMaven(f *os.File) ([]ptypes.Library, error) {
// 	libs, err := maven.Parse(f)
// 	if err != nil {
// 		return nil, xerrors.Errorf("invalid pom.xml format: %w", err)
// 	}
// 	return libs, nil
// }
//
// func (s *Scanner) parseGradle(f *os.File) ([]ptypes.Library, error) {
// 	libs, err := gradle.Parse(f)
// 	if err != nil {
// 		return nil, xerrors.Errorf("invalid build.gradle format: %w", err)
// 	}
// 	return libs, nil
// }

func (s *Scanner) Type() string {
	return s.scannerType
}
