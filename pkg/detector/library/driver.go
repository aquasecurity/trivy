package library

import (
	"strings"

	"github.com/samber/lo"
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
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// NewDriver returns a driver according to the library type
func NewDriver(libType ftypes.LangType) (Driver, bool) {
	var eco ecosystem.Type
	var comparer compare.Comparer

	switch libType {
	case ftypes.Bundler, ftypes.GemSpec:
		eco = ecosystem.RubyGems
		comparer = rubygems.Comparer{}
	case ftypes.RustBinary, ftypes.Cargo:
		eco = ecosystem.Cargo
		comparer = compare.GenericComparer{}
	case ftypes.Composer, ftypes.ComposerVendor:
		eco = ecosystem.Composer
		comparer = compare.GenericComparer{}
	case ftypes.GoBinary, ftypes.GoModule:
		eco = ecosystem.Go
		comparer = compare.GenericComparer{}
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle, ftypes.Sbt:
		eco = ecosystem.Maven
		comparer = maven.Comparer{}
	case ftypes.Npm, ftypes.Yarn, ftypes.Pnpm, ftypes.Bun, ftypes.NodePkg, ftypes.JavaScript:
		eco = ecosystem.Npm
		comparer = npm.Comparer{}
	case ftypes.NuGet, ftypes.DotNetCore, ftypes.PackagesProps:
		eco = ecosystem.NuGet
		comparer = compare.GenericComparer{}
	case ftypes.Pipenv, ftypes.Poetry, ftypes.Pip, ftypes.PythonPkg, ftypes.Uv, ftypes.PyLock:
		eco = ecosystem.Pip
		comparer = pep440.Comparer{}
	case ftypes.Pub:
		eco = ecosystem.Pub
		comparer = compare.GenericComparer{}
	case ftypes.Hex:
		eco = ecosystem.Erlang
		comparer = compare.GenericComparer{}
	case ftypes.Conan:
		eco = ecosystem.Conan
		// Only semver can be used for version ranges
		// https://docs.conan.io/en/latest/versioning/version_ranges.html
		comparer = compare.GenericComparer{}
	case ftypes.Swift:
		// Swift uses semver
		// https://www.swift.org/package-manager/#importing-dependencies
		eco = ecosystem.Swift
		comparer = compare.GenericComparer{}
	case ftypes.Cocoapods:
		// CocoaPods uses RubyGems version specifiers
		// https://guides.cocoapods.org/making/making-a-cocoapod.html#cocoapods-versioning-specifics
		eco = ecosystem.Cocoapods
		comparer = rubygems.Comparer{}
	case ftypes.CondaPkg, ftypes.CondaEnv:
		log.Warn("Conda package is supported for SBOM, not for vulnerability scanning")
		return Driver{}, false
	case ftypes.Bitnami:
		eco = ecosystem.Bitnami
		comparer = bitnami.Comparer{}
	case ftypes.K8sUpstream:
		eco = ecosystem.Kubernetes
		comparer = compare.GenericComparer{}
	case ftypes.Julia:
		eco = ecosystem.Julia
		comparer = compare.GenericComparer{}
	default:
		log.Warn("The library type is not supported for vulnerability scanning",
			log.String("type", string(libType)))
		return Driver{}, false
	}
	return Driver{
		ecosystem: eco,
		comparer:  comparer,
		dbc:       db.Config{},
	}, true
}

// Driver represents security advisories for each programming language
type Driver struct {
	ecosystem ecosystem.Type
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
func (d *Driver) DetectVulnerabilities(pkgID, pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	normalizedName := vulnerability.NormalizePkgName(d.ecosystem, pkgName)

	advisories, comparer, err := d.advisories(normalizedName, pkgVer)
	if err != nil {
		return nil, err
	}

	var vulns []types.DetectedVulnerability
	for _, adv := range advisories {
		if !comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  adv.VulnerabilityID,
			VendorIDs:        adv.VendorIDs, // Any vendors have specific IDs, e.g. GHSA, JLSEC
			PkgID:            pkgID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     createFixedVersions(adv),
			DataSource:       adv.DataSource,
			Custom:           adv.Custom,
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// advisories resolves the advisory bucket for the package and returns the
// matching advisories together with the version comparer to use.
//
// For vendor packages (e.g. Seal Security), it prefers the vendor-specific
// bucket and comparer. When the vendor match is only a candidate (a version
// suffix that can also appear on real packages, e.g. `-spN` on Go/npm), the
// vendor bucket is used only if it actually contains advisories for the
// package; otherwise it falls back to the default ecosystem bucket.
func (d *Driver) advisories(normalizedName, pkgVer string) ([]dbTypes.Advisory, compare.Comparer, error) {
	if v, res := lookupVendor(d.ecosystem, normalizedName, pkgVer); res != NoMatch {
		advisories, err := d.dbc.GetAdvisories(v.BucketPrefix(d.ecosystem), normalizedName)
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to get %s advisories: %w", d.ecosystem, err)
		}
		if res == Matched || len(advisories) > 0 {
			return advisories, v.Comparer(d.ecosystem, d.comparer), nil
		}
		// Candidate match without vendor advisories: fall back to the default bucket.
	}

	advisories, err := d.dbc.GetAdvisories(defaultBucketPrefix(d.ecosystem), normalizedName)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to get %s advisories: %w", d.ecosystem, err)
	}
	return advisories, d.comparer, nil
}

func createFixedVersions(advisory dbTypes.Advisory) string {
	if len(advisory.PatchedVersions) != 0 {
		return joinFixedVersions(advisory.PatchedVersions)
	}

	var fixedVersions []string
	for _, version := range advisory.VulnerableVersions {
		for s := range strings.SplitSeq(version, ",") {
			s = strings.TrimSpace(s)
			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
				s = strings.TrimPrefix(s, "<")
				fixedVersions = append(fixedVersions, strings.TrimSpace(s))
			}
		}
	}
	return joinFixedVersions(fixedVersions)
}

func joinFixedVersions(fixedVersions []string) string {
	return strings.Join(lo.Uniq(fixedVersions), ", ")
}
