package library

import (
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	ecosystem "github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/bundler"
	"github.com/aquasecurity/trivy/pkg/detector/library/cargo"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
	"github.com/aquasecurity/trivy/pkg/detector/library/composer"
	"github.com/aquasecurity/trivy/pkg/detector/library/ghsa"
	"github.com/aquasecurity/trivy/pkg/detector/library/maven"
	"github.com/aquasecurity/trivy/pkg/detector/library/npm"
	"github.com/aquasecurity/trivy/pkg/detector/library/python"
	"github.com/aquasecurity/trivy/pkg/types"
)

type advisory interface {
	DetectVulnerabilities(string, string) ([]types.DetectedVulnerability, error)
}

// NewDriver returns a driver according to the library type
func NewDriver(libType string) (Driver, error) {
	var driver Driver
	switch libType {
	case ftypes.Bundler:
		driver = newRubyGemsDriver()
	case ftypes.Cargo:
		driver = newCargoDriver()
	case ftypes.Composer:
		driver = newComposerDriver()
	case ftypes.Npm, ftypes.Yarn:
		driver = newNpmDriver()
	case ftypes.Pipenv, ftypes.Poetry:
		driver = newPipDriver()
	case ftypes.NuGet:
		driver = newNugetDriver()
	case ftypes.Jar:
		driver = newMavenDriver()
	case ftypes.GoBinary, ftypes.GoMod:
		driver = Driver{
			ecosystem:  vulnerability.Go,
			advisories: []advisory{NewAdvisory(vulnerability.Go, comparer.GenericComparer{})},
		}
	default:
		return Driver{}, xerrors.Errorf("unsupported type %s", libType)
	}
	return driver, nil
}

// Driver implements the advisory
type Driver struct {
	ecosystem  string
	advisories []advisory
}

// Aggregate aggregates drivers
func Aggregate(ecosystem string, advisories ...advisory) Driver {
	return Driver{ecosystem: ecosystem, advisories: advisories}
}

// Detect scans and returns vulnerabilities
func (d *Driver) Detect(pkgName string, pkgVer string) ([]types.DetectedVulnerability, error) {
	var detectedVulnerabilities []types.DetectedVulnerability
	uniqVulnIDMap := make(map[string]struct{})
	for _, adv := range d.advisories {
		vulns, err := adv.DetectVulnerabilities(pkgName, pkgVer)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect vulnerabilities: %w", err)
		}
		for _, vuln := range vulns {
			if _, ok := uniqVulnIDMap[vuln.VulnerabilityID]; ok {
				continue
			}
			uniqVulnIDMap[vuln.VulnerabilityID] = struct{}{}
			detectedVulnerabilities = append(detectedVulnerabilities, vuln)
		}
	}

	return detectedVulnerabilities, nil
}

// Type returns the driver ecosystem
func (d *Driver) Type() string {
	return d.ecosystem
}

func newRubyGemsDriver() Driver {
	c := bundler.RubyGemsComparer{}
	return Aggregate(vulnerability.RubyGems, ghsa.NewAdvisory(ecosystem.Rubygems, c), bundler.NewAdvisory(),
		NewAdvisory(vulnerability.RubyGems, c))
}

func newComposerDriver() Driver {
	c := comparer.GenericComparer{}
	return Aggregate(vulnerability.Composer, ghsa.NewAdvisory(ecosystem.Composer, c), composer.NewAdvisory(),
		NewAdvisory(vulnerability.Composer, c))
}

func newCargoDriver() Driver {
	return Aggregate(vulnerability.Cargo, cargo.NewAdvisory(),
		NewAdvisory(vulnerability.Cargo, comparer.GenericComparer{}))
}

func newNpmDriver() Driver {
	c := npm.Comparer{}
	return Aggregate(vulnerability.Npm, ghsa.NewAdvisory(ecosystem.Npm, c),
		npm.NewAdvisory(), NewAdvisory(vulnerability.Npm, c))
}

func newPipDriver() Driver {
	c := comparer.GenericComparer{}
	return Aggregate(vulnerability.Pip, ghsa.NewAdvisory(ecosystem.Pip, c),
		python.NewAdvisory(), NewAdvisory(vulnerability.Pip, c))
}

func newNugetDriver() Driver {
	c := comparer.GenericComparer{}
	return Aggregate(vulnerability.NuGet, ghsa.NewAdvisory(ecosystem.Nuget, c),
		NewAdvisory(vulnerability.NuGet, c))
}

func newMavenDriver() Driver {
	c := maven.Comparer{}
	return Aggregate(vulnerability.Maven, ghsa.NewAdvisory(ecosystem.Maven, c),
		NewAdvisory(vulnerability.Maven, c))
}
