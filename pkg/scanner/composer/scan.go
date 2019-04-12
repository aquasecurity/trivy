package composer

import (
	"fmt"
	"os"
	"strings"

	"github.com/knqyf263/trivy/pkg/scanner"

	"github.com/knqyf263/trivy/pkg/scanner/utils"

	"github.com/hashicorp/go-version"
	"github.com/knqyf263/trivy/pkg/types"
)

var (
	replacer = strings.NewReplacer(".beta", "-beta", ".rc", "-rc")
)

type Scanner struct {
	file *os.File
	db   AdvisoryDB
}

func NewComposerScanner(f *os.File) scanner.Scanner {
	return &Scanner{file: f}
}

func (c *Scanner) Scan(pkgs []types.Library) ([]types.Vulnerability, error) {
	var vulns []types.Vulnerability
	for _, pkg := range pkgs {
		ref := fmt.Sprintf("composer://%s", pkg.Name)
		for _, advisory := range c.db[ref] {
			v, err := version.NewVersion(pkg.Version)
			if err != nil {
				return nil, err
			}

			var affectedVersions []string
			for _, branch := range advisory.Branches {
				affectedVersions = append(affectedVersions, strings.Join(branch.Versions, ", "))

			}

			if !utils.MatchVersions(v, affectedVersions) {
				continue
			}

			vuln := types.Vulnerability{
				VulnerabilityID: advisory.Cve,
				LibraryName:     strings.TrimPrefix(advisory.Reference, "composer://"),
				Title:           strings.TrimSpace(advisory.Title),
				Url:             advisory.Link,
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}
