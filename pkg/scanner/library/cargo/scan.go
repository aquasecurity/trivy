package cargo

import (
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

	"github.com/aquasecurity/go-dep-parser/pkg/cargo"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/knqyf263/go-version"
	"golang.org/x/xerrors"
)

const (
	scannerType = "cargo"
)

type Scanner struct {
	db AdvisoryDB
}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]vulnerability.DetectedVulnerability, error) {
	var vulns []vulnerability.DetectedVulnerability
	for _, advisory := range s.db[pkgName] {
		if utils.MatchVersions(pkgVer, advisory.PatchedVersions) {
			continue
		}

		vuln := vulnerability.DetectedVulnerability{
			VulnerabilityID:  advisory.Id,
			PkgName:          strings.TrimSpace(advisory.Package),
			Title:            strings.TrimSpace(advisory.Title),
			InstalledVersion: pkgVer.String(),
			FixedVersion:     strings.Join(advisory.PatchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func (s *Scanner) ParseLockfile(f *os.File) ([]ptypes.Library, error) {
	libs, err := cargo.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid Cargo.lock format: %w", err)
	}
	return libs, nil
}

func (s *Scanner) Type() string {
	return scannerType
}
