package npm

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/knqyf263/go-dep-parser/pkg/npm"
	ptypes "github.com/knqyf263/go-dep-parser/pkg/types"
	"github.com/knqyf263/go-version"
	"github.com/knqyf263/trivy/pkg/scanner/utils"
	"github.com/knqyf263/trivy/pkg/types"
)

const (
	scannerType = "npm"
)

type Scanner struct {
	db AdvisoryDB
}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.Vulnerability, error) {
	replacer := strings.NewReplacer(".alpha", "-alpha", ".beta", "-beta", ".rc", "-rc", " <", ", <", " >", ", >")
	var vulns []types.Vulnerability
	for _, advisory := range s.db[pkgName] {
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

		if len(advisory.Cves) == 0 {
			advisory.Cves = []string{fmt.Sprintf("NSWG-ECO-%d", advisory.ID)}
		}

		for _, cveID := range advisory.Cves {
			vuln := types.Vulnerability{
				VulnerabilityID:  cveID,
				PkgName:          pkgName,
				Title:            strings.TrimSpace(advisory.Title),
				InstalledVersion: pkgVer.String(),
				FixedVersion:     strings.Join(patchedVersions, ", "),
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}

func (s *Scanner) ParseLockfile(f *os.File) ([]ptypes.Library, error) {
	libs, err := npm.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid package-lock.json format: %w", err)
	}
	return libs, nil
}
func (s *Scanner) Type() string {
	return scannerType
}
