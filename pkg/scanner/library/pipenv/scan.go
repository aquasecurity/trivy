package pipenv

import (
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/knqyf263/go-dep-parser/pkg/pipenv"
	ptypes "github.com/knqyf263/go-dep-parser/pkg/types"
	"github.com/knqyf263/go-version"
	"github.com/knqyf263/trivy/pkg/scanner/utils"
	"github.com/knqyf263/trivy/pkg/types"
)

const (
	scannerType = "pipenv"
)

type Scanner struct {
	db AdvisoryDB
}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.Vulnerability, error) {
	var vulns []types.Vulnerability
	for _, advisory := range s.db[pkgName] {
		if !utils.MatchVersions(pkgVer, advisory.Specs) {
			continue
		}

		vulnerabilityID := advisory.Cve
		if vulnerabilityID == "" {
			vulnerabilityID = advisory.ID
		}

		vuln := types.Vulnerability{
			VulnerabilityID:  vulnerabilityID,
			PkgName:          pkgName,
			Title:            strings.TrimSpace(advisory.Advisory),
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
	libs, err := pipenv.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid Pipfile.lock format: %w", err)
	}
	return libs, nil
}
func (s *Scanner) Type() string {
	return scannerType
}
