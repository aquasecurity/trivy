package gem

import (
	"bufio"
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

func (g *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.Vulnerability, error) {
	var vulns []types.Vulnerability
	for _, advisory := range g.db[pkgName] {
		if utils.MatchVersions(pkgVer, advisory.PatchedVersions) {
			continue
		}
		if utils.MatchVersions(pkgVer, advisory.UnaffectedVersions) {
			continue
		}

		var vulnerabilityID string
		if advisory.Cve != "" {
			vulnerabilityID = fmt.Sprintf("CVE-%s", advisory.Cve)
		} else if advisory.Osvdb != "" {
			vulnerabilityID = fmt.Sprintf("OSVDB-%s", advisory.Osvdb)
		}

		vuln := types.Vulnerability{
			VulnerabilityID: vulnerabilityID,
			LibraryName:     strings.TrimSpace(advisory.Gem),
			Title:           strings.TrimSpace(advisory.Title),
			Url:             advisory.Url,
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func (g *Scanner) ParseLockfile() ([]types.Library, error) {
	var libs []types.Library
	scanner := bufio.NewScanner(g.file)
	for scanner.Scan() {
		line := scanner.Text()
		if countLeadingSpace(line) == 4 {
			line = strings.TrimSpace(line)
			s := strings.Fields(line)
			if len(s) != 2 {
				continue
			}
			libs = append(libs, types.Library{
				Name:    s[0],
				Version: strings.Trim(s[1], "()"),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return libs, nil
}

func countLeadingSpace(line string) int {
	i := 0
	for _, runeValue := range line {
		if runeValue == ' ' {
			i++
		} else {
			break
		}
	}
	return i
}
