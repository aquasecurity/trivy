package library

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Advisory represents security advisories for each programming language
type Advisory struct {
	lang     string
	comparer comparer
}

func NewAdvisory(lang string) *Advisory {
	return &Advisory{
		lang:     lang,
		comparer: newComparer(lang),
	}
}

// DetectVulnerabilities scans buckets with the prefix according to the programming language in "Advisory".
// If "lang" is python, it looks for buckets with "python::" and gets security advisories from those buckets.
// It allows us to add a new data source with the lang prefix (e.g. python::new-data-source)
// and detect vulnerabilities without specifying a specific bucket name.
func (s *Advisory) DetectVulnerabilities(pkgName string, pkgVer *semver.Version) ([]types.DetectedVulnerability, error) {
	// e.g. "python::"
	prefix := fmt.Sprintf("%s::", s.lang)
	advisories, err := db.Config{}.GetAdvisories(prefix, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", s.lang, err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		if !s.comparer.isVulnerable(pkgVer, advisory) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer.String(),
			FixedVersion:     s.createFixedVersions(advisory),
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

func (s *Advisory) createFixedVersions(advisory dbTypes.Advisory) string {
	if len(advisory.PatchedVersions) != 0 {
		return strings.Join(advisory.PatchedVersions, ", ")
	}

	var fixedVersions []string
	for _, version := range advisory.VulnerableVersions {
		for _, s := range strings.Split(version, ",") {
			s = strings.TrimSpace(s)
			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
				s = strings.TrimPrefix(s, "<")
				fixedVersions = append(fixedVersions, strings.TrimSpace(s))
			}
		}
	}
	return strings.Join(fixedVersions, ", ")
}

type comparer interface {
	isVulnerable(pkgVer *semver.Version, advisory dbTypes.Advisory) bool
}

func newComparer(lang string) comparer {
	switch lang {
	// When another library is needed for version comparison, it can be added here.
	}
	return generalComparer{}
}

type generalComparer struct{}

func (c generalComparer) isVulnerable(pkgVer *semver.Version, advisory dbTypes.Advisory) bool {
	if len(advisory.VulnerableVersions) != 0 {
		return utils.MatchVersions(pkgVer, advisory.VulnerableVersions)
	}

	if utils.MatchVersions(pkgVer, advisory.PatchedVersions) ||
		utils.MatchVersions(pkgVer, advisory.UnaffectedVersions) {
		return false
	}

	return true
}
