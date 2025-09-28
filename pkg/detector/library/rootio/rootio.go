package rootio

import (
	"fmt"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/bitnami"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/maven"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/rubygems"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// DBInterface defines methods needed for database operations
type DBInterface interface {
	GetAdvisories(prefix, pkgName string) ([]dbTypes.Advisory, error)
}

// Scanner implements the Root.io scanner for language packages
// It uses the standard advisory fetching but with rootio-specific logic
type Scanner struct {
	ecosystem dbTypes.Ecosystem
	comparer  compare.Comparer
	dbc       DBInterface
	logger    *log.Logger
}

// NewScanner is the factory method for Scanner
func NewScanner(ecosystem dbTypes.Ecosystem, comparer compare.Comparer) *Scanner {
	return &Scanner{
		ecosystem: ecosystem,
		comparer:  comparer,
		dbc:       db.Config{},
		logger:    log.WithPrefix("rootio-" + string(ecosystem)),
	}
}

// getComparerForEcosystem returns the appropriate comparer for each ecosystem
func getComparerForEcosystem(ecosystem dbTypes.Ecosystem) compare.Comparer {
	switch ecosystem {
	case vulnerability.RubyGems:
		return rubygems.Comparer{}
	case vulnerability.Pip:
		return pep440.Comparer{}
	case vulnerability.Npm:
		return npm.Comparer{}
	case vulnerability.Maven:
		return maven.Comparer{}
	case vulnerability.Bitnami:
		return bitnami.Comparer{}
	case vulnerability.Cocoapods:
		return rubygems.Comparer{} // CocoaPods uses RubyGems version specifiers
	default:
		// Default to generic semver comparison
		return compare.GenericComparer{}
	}
}

// Type returns the scanner ecosystem
func (s *Scanner) Type() string {
	return string(s.ecosystem)
}

// DetectVulnerabilities scans packages for vulnerabilities with Root.io-specific handling
func (s *Scanner) DetectVulnerabilities(pkgID, pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	// Strip .root.io suffix from version for comparison
	baseVersion := NormalizeVersion(pkgVer)

	// Get advisories using standard ecosystem prefix
	// This will look for buckets like "pip::", "npm::", etc.
	// In the future, when trivy-db supports it, this could look for "pip::rootio"
	prefix := fmt.Sprintf("%s::", s.ecosystem)
	advisories, err := s.dbc.GetAdvisories(prefix, vulnerability.NormalizePkgName(s.ecosystem, pkgName))
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", s.ecosystem, err)
	}

	var vulns []types.DetectedVulnerability
	for _, adv := range advisories {
		// Check if the base version (without .root.io) is vulnerable
		if !s.comparer.IsVulnerable(baseVersion, adv) {
			continue
		}

		// For rootio packages, append .root.io to fixed versions if not present
		fixedVersion := s.createRootIOFixedVersions(adv)

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  adv.VulnerabilityID,
			PkgID:            pkgID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     fixedVersion,
			DataSource:       adv.DataSource,
			Custom:           adv.Custom,
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// createRootIOFixedVersions creates fixed versions with .root.io suffix
func (s *Scanner) createRootIOFixedVersions(advisory dbTypes.Advisory) string {
	if len(advisory.PatchedVersions) != 0 {
		// Add .root.io suffix to patched versions if not present
		var fixedVersions []string
		for _, v := range advisory.PatchedVersions {
			v = AddVersionSuffix(v)
			fixedVersions = append(fixedVersions, v)
		}
		return strings.Join(lo.Uniq(fixedVersions), ", ")
	}

	// Extract fixed versions from vulnerable version constraints
	var fixedVersions []string
	for _, version := range advisory.VulnerableVersions {
		for s := range strings.SplitSeq(version, ",") {
			s = strings.TrimSpace(s)
			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
				s = strings.TrimPrefix(s, "<")
				s = strings.TrimSpace(s)
				// Add .root.io suffix to indicate this is a rootio fix
				s = AddVersionSuffix(s)
				fixedVersions = append(fixedVersions, s)
			}
		}
	}
	return strings.Join(lo.Uniq(fixedVersions), ", ")
}
