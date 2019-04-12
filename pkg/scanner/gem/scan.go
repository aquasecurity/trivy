package gem

import (
	"fmt"
	"os"
	"strings"

	"github.com/knqyf263/trivy/pkg/scanner/utils"

	"github.com/hashicorp/go-version"
	"github.com/knqyf263/trivy/pkg/scanner"
	"github.com/knqyf263/trivy/pkg/types"
)

type Scanner struct {
	file *os.File
	db   AdvisoryDB
}

func NewGemScanner(f *os.File) scanner.Scanner {
	return &Scanner{file: f}
}

func (g *Scanner) Scan(pkgs []types.Library) ([]types.Vulnerability, error) {
	var vulns []types.Vulnerability
	for _, pkg := range pkgs {
		for _, advisory := range g.db[pkg.Name] {
			v, err := version.NewVersion(pkg.Version)
			if err != nil {
				return nil, err
			}

			if utils.MatchVersions(v, advisory.PatchedVersions) {
				continue
			}
			if utils.MatchVersions(v, advisory.UnaffectedVersions) {
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
	}
	return vulns, nil
}
