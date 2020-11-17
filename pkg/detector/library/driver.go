package library

import (
	"fmt"

	"golang.org/x/xerrors"

	ecosystem "github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/bundler"
	"github.com/aquasecurity/trivy/pkg/detector/library/cargo"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
	"github.com/aquasecurity/trivy/pkg/detector/library/composer"
	"github.com/aquasecurity/trivy/pkg/detector/library/ghsa"
	"github.com/aquasecurity/trivy/pkg/detector/library/node"
	"github.com/aquasecurity/trivy/pkg/detector/library/python"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Factory defines library operations
type Factory interface {
	NewDriver(filename string) (Driver, error)
}

type advisory interface {
	DetectVulnerabilities(string, string) ([]types.DetectedVulnerability, error)
}

// DriverFactory implements Factory
type DriverFactory struct{}

// NewDriver factory method for driver
func (d DriverFactory) NewDriver(filename string) (Driver, error) {
	var driver Driver
	switch filename {
	case "Gemfile.lock":
		driver = newRubyGemsDriver()
	case "Cargo.lock":
		driver = newCargoDriver()
	case "composer.lock":
		driver = newComposerDriver()
	case "package-lock.json", "yarn.lock":
		driver = newNpmDriver()
	case "Pipfile.lock", "poetry.lock":
		driver = newPipDriver()
	default:
		return Driver{}, xerrors.New(fmt.Sprintf("unsupport filename %s", filename))
	}
	return driver, nil
}

// Driver implements the advisory
type Driver struct {
	ecosystem  string
	advisories []advisory
}

// NewDriver is the factory method from drier
func NewDriver(advisories ...advisory) Driver {
	return Driver{advisories: advisories}
}

// Detect scans and returns vulnerabilities
func (d *Driver) Detect(pkgName string, pkgVer string) ([]types.DetectedVulnerability, error) {
	var detectedVulnerabilities []types.DetectedVulnerability
	uniqVulnIDMap := make(map[string]struct{})
	for _, d := range d.advisories {
		vulns, err := d.DetectVulnerabilities(pkgName, pkgVer)
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
	return NewDriver(ghsa.NewAdvisory(ecosystem.Rubygems, c), bundler.NewAdvisory(),
		NewAdvisory(vulnerability.RubyGems, c))
}

func newComposerDriver() Driver {
	c := comparer.GenericComparer{}
	return NewDriver(
		ghsa.NewAdvisory(ecosystem.Composer, c), composer.NewAdvisory(),
		NewAdvisory(vulnerability.Composer, c))
}

func newCargoDriver() Driver {
	return NewDriver(cargo.NewAdvisory(), NewAdvisory(vulnerability.Cargo, comparer.GenericComparer{}))
}

func newNpmDriver() Driver {
	c := node.NpmComparer{}
	return NewDriver(ghsa.NewAdvisory(ecosystem.Npm, c), node.NewAdvisory(),
		NewAdvisory(vulnerability.Npm, c))
}

func newPipDriver() Driver {
	c := comparer.GenericComparer{}
	return NewDriver(ghsa.NewAdvisory(ecosystem.Pip, c), python.NewAdvisory(),
		NewAdvisory(vulnerability.Pip, c))
}
