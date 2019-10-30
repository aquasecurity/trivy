package python

import (
	"os"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/python"
	"github.com/aquasecurity/trivy/pkg/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/pipenv"
	"github.com/aquasecurity/go-dep-parser/pkg/poetry"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/knqyf263/go-version"
)

const (
	ScannerTypePipenv = "pipenv"
	ScannerTypePoetry = "poetry"
)

type Scanner struct {
	scannerType string
	vs          python.VulnSrc
}

func NewScanner(scannerType string) *Scanner {
	return &Scanner{scannerType: scannerType}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error) {
	advisories, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", s.Type(), err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		if !utils.MatchVersions(pkgVer, advisory.Specs) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer.String(),
			FixedVersion:     createFixedVersions(advisory.Specs),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func createFixedVersions(specs []string) string {
	var fixedVersions []string
	for _, spec := range specs {
		for _, s := range strings.Split(spec, ",") {
			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
				fixedVersions = append(fixedVersions, strings.TrimPrefix(s, "<"))
			}
		}
	}
	return strings.Join(fixedVersions, ", ")
}

func (s *Scanner) ParseLockfile(f *os.File) ([]ptypes.Library, error) {
	if s.Type() == ScannerTypePipenv {
		return s.parsePipenv(f)
	}
	return s.parsePoetry(f)
}

func (s *Scanner) parsePipenv(f *os.File) ([]ptypes.Library, error) {
	libs, err := pipenv.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid Pipfile.lock format: %w", err)
	}
	return libs, nil
}

func (s *Scanner) parsePoetry(f *os.File) ([]ptypes.Library, error) {
	libs, err := poetry.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid poetry.lock format: %w", err)
	}
	return libs, nil
}

func (s *Scanner) Type() string {
	return s.scannerType
}
