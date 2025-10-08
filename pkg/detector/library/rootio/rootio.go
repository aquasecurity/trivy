package rootio

import (
	"fmt"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
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
type Scanner struct {
	ecosystem ecosystem.Type
	comparer  compare.Comparer
	dbc       DBInterface
	logger    *log.Logger
}

// NewScanner is the factory method for Scanner
func NewScanner(eco ecosystem.Type, comparer compare.Comparer) *Scanner {
	return &Scanner{
		ecosystem: eco,
		comparer:  comparer,
		dbc:       db.Config{},
		logger:    log.WithPrefix("rootio-" + string(eco)),
	}
}

// getComparerForEcosystem returns the appropriate comparer for each ecosystem
func getComparerForEcosystem(eco ecosystem.Type) compare.Comparer {
	switch eco {
	case ecosystem.RubyGems:
		return rubygems.Comparer{}
	case ecosystem.Pip:
		return pep440.Comparer{}
	case ecosystem.Npm:
		return npm.Comparer{}
	case ecosystem.Maven:
		return maven.Comparer{}
	case ecosystem.Bitnami:
		return bitnami.Comparer{}
	case ecosystem.Cocoapods:
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
	// Get advisories using standard ecosystem prefix
	prefix := fmt.Sprintf("%s::", s.ecosystem)
	advisories, err := s.dbc.GetAdvisories(prefix, vulnerability.NormalizePkgName(s.ecosystem, pkgName))
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", s.ecosystem, err)
	}

	var vulns []types.DetectedVulnerability
	for _, adv := range advisories {
		// Check if the version is vulnerable using the normalized version
		if !s.comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		fixedVersion := strings.Join(adv.PatchedVersions, ", ")

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
