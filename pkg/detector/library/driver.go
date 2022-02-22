package library

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare/maven"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/rubygems"
	"github.com/aquasecurity/trivy/pkg/types"
)

// NewDriver returns a driver according to the library type
func NewDriver(libType string) (Driver, error) {
	var ecosystem dbTypes.Ecosystem
	var comparer compare.Comparer

	switch libType {
	case ftypes.Bundler, ftypes.GemSpec:
		ecosystem = vulnerability.RubyGems
		comparer = rubygems.Comparer{}
	case ftypes.Cargo:
		ecosystem = vulnerability.Cargo
		comparer = compare.GenericComparer{}
	case ftypes.Composer:
		ecosystem = vulnerability.Composer
		comparer = compare.GenericComparer{}
	case ftypes.GoBinary, ftypes.GoMod:
		ecosystem = vulnerability.Go
		comparer = compare.GenericComparer{}
	case ftypes.Jar, ftypes.Pom:
		ecosystem = vulnerability.Maven
		comparer = maven.Comparer{}
	case ftypes.Npm, ftypes.Yarn, ftypes.NodePkg, ftypes.JavaScript:
		ecosystem = vulnerability.Npm
		comparer = npm.Comparer{}
	case ftypes.NuGet:
		ecosystem = vulnerability.NuGet
		comparer = compare.GenericComparer{}
	case ftypes.Pipenv, ftypes.Poetry, ftypes.Pip, ftypes.PythonPkg:
		ecosystem = vulnerability.Pip
		comparer = pep440.Comparer{}
	default:
		return Driver{}, xerrors.Errorf("unsupported type %s", libType)
	}
	return Driver{
		ecosystem: ecosystem,
		comparer:  comparer,
		dbc:       db.Config{},
	}, nil
}

// Driver represents security advisories for each programming language
type Driver struct {
	ecosystem dbTypes.Ecosystem
	comparer  compare.Comparer
	dbc       db.Config
}

// Type returns the driver ecosystem
func (d *Driver) Type() string {
	return string(d.ecosystem)
}

// DetectVulnerabilities scans buckets with the prefix according to the ecosystem.
// If "ecosystem" is pip, it looks for buckets with "pip::" and gets security advisories from those buckets.
// It allows us to add a new data source with the ecosystem prefix (e.g. pip::new-data-source)
// and detect vulnerabilities without specifying a specific bucket name.
func (d *Driver) DetectVulnerabilities(pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	// e.g. "pip::", "npm::"
	prefix := fmt.Sprintf("%s::", d.ecosystem)
	advisories, err := d.dbc.GetAdvisories(prefix, vulnerability.NormalizePkgName(d.ecosystem, pkgName))
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", d.ecosystem, err)
	}

	var vulns []types.DetectedVulnerability
	for _, adv := range advisories {
		if !d.comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  adv.VulnerabilityID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     createFixedVersions(adv),
			DataSource:       adv.DataSource,
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

func createFixedVersions(advisory dbTypes.Advisory) string {
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
