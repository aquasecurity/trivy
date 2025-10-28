package rootio

import (
	"context"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/rootio"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/bitnami"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/maven"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/rubygems"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner implements the Root.io driver for language packages
type Scanner struct {
	ecosystem ecosystem.Type
	comparer  compare.Comparer
	logger    *log.Logger
}

// NewScanner is the factory method for Scanner
func NewScanner(eco ecosystem.Type) Scanner {
	return Scanner{
		ecosystem: eco,
		comparer:  comparer(eco),
		logger:    log.WithPrefix("rootio-" + string(eco)),
	}
}

// comparer returns the appropriate comparer for each ecosystem
func comparer(eco ecosystem.Type) compare.Comparer {
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
func (d Scanner) Type() string {
	return string(d.ecosystem)
}

// Detect scans packages for vulnerabilities with Root.io-specific handling
func (d Scanner) Detect(_ context.Context, pkg ftypes.Package) ([]types.DetectedVulnerability, error) {
	getter := rootio.NewVulnSrcGetter(d.ecosystem)
	advisories, err := getter.Get(db.GetParams{
		PkgName: vulnerability.NormalizePkgName(d.ecosystem, pkg.Name),
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", d.ecosystem, err)
	}

	var vulns []types.DetectedVulnerability
	for _, adv := range advisories {
		// Check if the version is vulnerable using the normalized version
		if !d.comparer.IsVulnerable(pkg.Version, adv) {
			continue
		}

		fixedVersion := strings.Join(adv.PatchedVersions, ", ")

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  adv.VulnerabilityID,
			PkgID:            pkg.ID,
			PkgName:          pkg.Name,
			InstalledVersion: pkg.Version,
			FixedVersion:     fixedVersion,
			Layer:            pkg.Layer,
			PkgPath:          pkg.FilePath,
			PkgIdentifier:    pkg.Identifier,
			DataSource:       adv.DataSource,
			Custom:           adv.Custom,
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}
