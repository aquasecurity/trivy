package gem

import (
	"fmt"
	"os"
	"strings"

	"github.com/knqyf263/trivy/pkg/types"

	"github.com/Masterminds/semver"
)

func Scan(f *os.File) ([]types.Vulnerability, error) {
	var err error
	db, err := UpdateDB()
	if err != nil {
		return nil, err
	}

	pkgs, err := ParseLockfile(f)
	if err != nil {
		return nil, err
	}

	var vulns []types.Vulnerability
	for _, pkg := range pkgs {
		for _, advisory := range db[pkg.Name] {
			fmt.Println(advisory.Gem)
			v, err := semver.NewVersion(normalizeVersion(pkg.Version))
			if err != nil {
				return nil, err
			}

			var match bool
			if match, err = matchVersions(v, advisory.PatchedVersions); err != nil {
				return nil, err
			}
			if match {
				continue
			}

			if match, err = matchVersions(v, advisory.UnaffectedVersions); err != nil {
				return nil, err
			}
			if match {
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
				LibraryName:     advisory.Gem,
				Title:           strings.TrimSpace(advisory.Title),
				Url:             advisory.Url,
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}

func matchVersions(currentVersion *semver.Version, rangeVersions []string) (bool, error) {
	if len(rangeVersions) == 0 {
		return false, nil
	}
	var versions []string
	for _, v := range rangeVersions {
		versions = append(versions, normalizeConstraint(v))
	}
	constraint := strings.Join(versions, " || ")
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, err
	}
	return c.Check(currentVersion), nil
}

func normalizeConstraint(constraint string) string {
	var constraints []string
	for _, c := range strings.Split(constraint, ", ") {
		constraints = append(constraints, normalizeVersion(c))
	}
	return strings.Join(constraints, ", ")
}

func normalizeVersion(v string) string {
	s := strings.SplitN(v, ".", 3)
	if len(s) == 3 {
		s[2] = strings.Replace(s[2], ".", "-", 1)
	}
	return strings.Join(s, ".")
}
