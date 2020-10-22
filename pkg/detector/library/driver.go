package library

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/xerrors"

	ecosystem "github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/bundler"
	"github.com/aquasecurity/trivy/pkg/detector/library/cargo"
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
	DetectVulnerabilities(string, *semver.Version) ([]types.DetectedVulnerability, error)
}

// DriverFactory implements Factory
type DriverFactory struct{}

// NewDriver factory method for driver
func (d DriverFactory) NewDriver(filename string) (Driver, error) {
	// TODO: use DI
	var driver Driver
	switch filename {
	case "Gemfile.lock":
		driver = newRubyDriver()
	case "Cargo.lock":
		driver = newRustDriver()
	case "composer.lock":
		driver = newPHPDriver()
	case "package-lock.json", "yarn.lock":
		driver = newNodejsDriver()
	case "Pipfile.lock", "poetry.lock":
		driver = newPythonDriver()
	default:
		return Driver{}, xerrors.New(fmt.Sprintf("unsupport filename %s", filename))
	}
	return driver, nil
}

// Driver implements the advisory
type Driver struct {
	lang       string
	advisories []advisory
}

// NewDriver is the factory method from drier
func NewDriver(lang string, advisories ...advisory) Driver {
	return Driver{lang: lang, advisories: advisories}
}

// Detect scans and returns vulnerabilities
func (d *Driver) Detect(pkgName string, pkgVer *semver.Version) ([]types.DetectedVulnerability, error) {
	var detectedVulnerabilities []types.DetectedVulnerability
	uniqVulnIDMap := make(map[string]struct{})
	for _, d := range append(d.advisories, NewAdvisory(d.lang)) {
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

// Type returns the driver lang
func (d *Driver) Type() string {
	return d.lang
}

func newRubyDriver() Driver {
	return NewDriver(vulnerability.Ruby, ghsa.NewAdvisory(ecosystem.Rubygems), bundler.NewAdvisory())
}

func newPHPDriver() Driver {
	return NewDriver(vulnerability.PHP, ghsa.NewAdvisory(ecosystem.Composer), composer.NewAdvisory())
}

func newRustDriver() Driver {
	return NewDriver(vulnerability.Rust, cargo.NewAdvisory())
}

func newNodejsDriver() Driver {
	return NewDriver(vulnerability.Nodejs, ghsa.NewAdvisory(ecosystem.Npm), node.NewAdvisory())
}

func newPythonDriver() Driver {
	return NewDriver(vulnerability.Python, ghsa.NewAdvisory(ecosystem.Pip), python.NewAdvisory())
}
