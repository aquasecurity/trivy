package library

import (
	"fmt"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Advisory represents security advisories for each programming language
type Advisory struct {
	ecosystem string
	comparer  comparer.Comparer
}

// NewAdvisory is the factory method of Advisory
func NewAdvisory(ecosystem string, comparer comparer.Comparer) *Advisory {
	return &Advisory{
		ecosystem: ecosystem,
		comparer:  comparer,
	}
}

// DetectVulnerabilities scans buckets with the prefix according to the ecosystem in "Advisory".
// If "ecosystem" is pip, it looks for buckets with "pip::" and gets security advisories from those buckets.
// It allows us to add a new data source with the ecosystem prefix (e.g. pip::new-data-source)
// and detect vulnerabilities without specifying a specific bucket name.
func (s *Advisory) DetectVulnerabilities(pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	// e.g. "pip::", "npm::"
	prefix := fmt.Sprintf("%s::", s.ecosystem)
	advisories, err := db.Config{}.GetAdvisories(prefix, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", s.ecosystem, err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		if !s.comparer.IsVulnerable(pkgVer, advisory) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
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
