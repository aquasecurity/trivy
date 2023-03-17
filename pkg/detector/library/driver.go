package library

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare/maven"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/rubygems"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

var comparers = map[string]compare.Comparer{
	ftypes.Bundler:    rubygems.Comparer{},
	ftypes.GemSpec:    rubygems.Comparer{},
	ftypes.RustBinary: compare.GenericComparer{},
	ftypes.Cargo:      compare.GenericComparer{},
	ftypes.Composer:   compare.GenericComparer{},
	ftypes.GoBinary:   compare.GenericComparer{},
	ftypes.GoModule:   compare.GenericComparer{},
	ftypes.Jar:        maven.Comparer{},
	ftypes.Pom:        maven.Comparer{},
	ftypes.Gradle:     maven.Comparer{},
	ftypes.Npm:        npm.Comparer{},
	ftypes.Yarn:       npm.Comparer{},
	ftypes.Pnpm:       npm.Comparer{},
	ftypes.NodePkg:    npm.Comparer{},
	ftypes.JavaScript: npm.Comparer{},
	ftypes.NuGet:      compare.GenericComparer{},
	ftypes.DotNetCore: compare.GenericComparer{},
	ftypes.Pipenv:     pep440.Comparer{},
	ftypes.Poetry:     pep440.Comparer{},
	ftypes.Pip:        pep440.Comparer{},
	ftypes.PythonPkg:  pep440.Comparer{},
}

func RegisterComparer(name string, comparer compare.Comparer) {
	comparers[name] = comparer
}

// NewDriver returns a driver according to the library type
func NewDriver(libType string) (Driver, error) {
	var ecosystem dbTypes.Ecosystem
	switch libType {
	case ftypes.Bundler, ftypes.GemSpec:
		ecosystem = vulnerability.RubyGems
	case ftypes.RustBinary, ftypes.Cargo:
		ecosystem = vulnerability.Cargo
	case ftypes.Composer:
		ecosystem = vulnerability.Composer
	case ftypes.GoBinary, ftypes.GoModule:
		ecosystem = vulnerability.Go
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle:
		ecosystem = vulnerability.Maven
	case ftypes.Npm, ftypes.Yarn, ftypes.Pnpm, ftypes.NodePkg, ftypes.JavaScript:
		ecosystem = vulnerability.Npm
	case ftypes.NuGet, ftypes.DotNetCore:
		ecosystem = vulnerability.NuGet
	case ftypes.Pipenv, ftypes.Poetry, ftypes.Pip, ftypes.PythonPkg:
		ecosystem = vulnerability.Pip
	case ftypes.Conan:
		ecosystem = vulnerability.Conan
		// Only semver can be used for version ranges
		// https://docs.conan.io/en/latest/versioning/version_ranges.html
	default:
		return Driver{}, xerrors.Errorf("unsupported type %s", libType)
	}
	return Driver{
		ecosystem: ecosystem,
		comparer:  comparers[libType],
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
func (d *Driver) DetectVulnerabilities(pkgID, pkgName, pkgVer string, os ftypes.OS) ([]types.DetectedVulnerability, error) {
	// e.g. "pip::", "npm::"
	prefix := fmt.Sprintf("%s::", d.ecosystem)
	advisories, err := d.dbc.GetAdvisories(prefix, vulnerability.NormalizePkgName(d.ecosystem, pkgName))
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", d.ecosystem, err)
	}

	compare.SetOSDetails(os)
	var vulns []types.DetectedVulnerability
	for _, adv := range advisories {
		if !d.comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  adv.VulnerabilityID,
			PkgID:            pkgID,
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
