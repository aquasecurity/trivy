package node

import (
	"os"
	"strings"

	version "github.com/knqyf263/go-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/npm"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/yarn"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/node"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	ScannerTypeNpm  = "npm"
	ScannerTypeYarn = "yarn"
)

type Scanner struct {
	scannerType string
	vs          node.VulnSrc
}

func NewScanner(scannerType string) *Scanner {
	return &Scanner{scannerType: scannerType}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error) {
	replacer := strings.NewReplacer(".alpha", "-alpha", ".beta", "-beta", ".rc", "-rc", " <", ", <", " >", ", >")
	advisories, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", s.Type(), err)
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

func (s *Scanner) ParseLockfile(f *os.File) ([]ptypes.Library, error) {
	if s.Type() == ScannerTypeNpm {
		return s.parseNpm(f)
	}
	return s.parseYarn(f)
}

func (s *Scanner) parseNpm(f *os.File) ([]ptypes.Library, error) {
	libs, err := npm.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid package-lock.json format: %w", err)
	}
	return libs, nil
}

func (s *Scanner) parseYarn(f *os.File) ([]ptypes.Library, error) {
	libs, err := yarn.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid yarn.lock format: %w", err)
	}
	return libs, nil
}

func (s *Scanner) Type() string {
	return s.scannerType
}
