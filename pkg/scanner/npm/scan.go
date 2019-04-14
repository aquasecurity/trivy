package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/knqyf263/go-version"
	t "github.com/knqyf263/trivy/pkg/scanner/types"
	"github.com/knqyf263/trivy/pkg/scanner/utils"
	"github.com/knqyf263/trivy/pkg/types"
)

type Scanner struct {
	file *os.File
	db   AdvisoryDB
}

func NewScanner(f *os.File) t.Scanner {
	return &Scanner{file: f}
}

func (n *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.Vulnerability, error) {
	replacer := strings.NewReplacer(".alpha", "-alpha", ".beta", "-beta", ".rc", "-rc", " <", ", <", " >", ", >")
	var vulns []types.Vulnerability
	for _, advisory := range n.db[pkgName] {
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
				VulnerabilityID: cveID,
				LibraryName:     pkgName,
				Title:           strings.TrimSpace(advisory.Title),
				Score:           advisory.CvssScore,
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}

type LockFile struct {
	Dependencies map[string]Dependency
}
type Dependency struct {
	Version string
	Dev     bool
}

func (n *Scanner) ParseLockfile() ([]types.Library, error) {
	var lockFile LockFile
	decoder := json.NewDecoder(n.file)
	err := decoder.Decode(&lockFile)
	if err != nil {
		return nil, err
	}

	var libs []types.Library
	for pkgName, dependency := range lockFile.Dependencies {
		libs = append(libs, types.Library{
			Name:    pkgName,
			Version: dependency.Version,
		})
	}
	return libs, nil
}
