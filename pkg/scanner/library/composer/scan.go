package composer

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/composer"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/knqyf263/go-version"
)

const (
	scannerType = "composer"
)

type Scanner struct {
	db AdvisoryDB
}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]vulnerability.DetectedVulnerability, error) {
	var vulns []vulnerability.DetectedVulnerability
	ref := fmt.Sprintf("composer://%s", pkgName)
	for _, advisory := range s.db[ref] {
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

		vuln := vulnerability.DetectedVulnerability{
			VulnerabilityID:  advisory.Cve,
			PkgName:          pkgName,
			Title:            strings.TrimSpace(advisory.Title),
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
