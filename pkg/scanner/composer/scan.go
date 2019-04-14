package composer

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

func (c *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.Vulnerability, error) {
	var vulns []types.Vulnerability
	ref := fmt.Sprintf("composer://%s", pkgName)
	for _, advisory := range c.db[ref] {
		var affectedVersions []string
		for _, branch := range advisory.Branches {
			affectedVersions = append(affectedVersions, strings.Join(branch.Versions, ", "))
		}

		if !utils.MatchVersions(pkgVer, affectedVersions) {
			continue
		}

		vuln := types.Vulnerability{
			VulnerabilityID: advisory.Cve,
			LibraryName:     pkgName,
			Title:           strings.TrimSpace(advisory.Title),
			Url:             advisory.Link,
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

type LockFile struct {
	Packages []Package
}
type Package struct {
	Name    string
	Version string
}

func (c *Scanner) ParseLockfile() ([]types.Library, error) {
	var lockFile LockFile
	decoder := json.NewDecoder(c.file)
	err := decoder.Decode(&lockFile)
	if err != nil {
		return nil, err
	}

	var libs []types.Library
	for _, pkg := range lockFile.Packages {
		libs = append(libs, types.Library{
			Name:    pkg.Name,
			Version: pkg.Version,
		})
	}
	return libs, nil
}
