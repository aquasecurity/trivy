package library

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
	ecosystem "github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/bundler"
	"github.com/aquasecurity/trivy/pkg/detector/library/cargo"
	"github.com/aquasecurity/trivy/pkg/detector/library/composer"
	"github.com/aquasecurity/trivy/pkg/detector/library/ghsa"
	"github.com/aquasecurity/trivy/pkg/detector/library/node"
	"github.com/aquasecurity/trivy/pkg/detector/library/python"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
)

type Factory interface {
	NewDriver(filename string) (Driver, error)
}

type advisory interface {
	DetectVulnerabilities(string, *semver.Version) ([]types.DetectedVulnerability, error)
}

type DriverFactory struct{}

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

type Driver struct {
	lang       string
	advisories []advisory
}

func NewDriver(lang string, advisories ...advisory) Driver {
	return Driver{lang: lang, advisories: advisories}
}

func (d *Driver) Detect(pkgName string, pkgVer *semver.Version) ([]types.DetectedVulnerability, error) {
	var detectedVulnerabilities []types.DetectedVulnerability
	uniqVulnIdMap := make(map[string]struct{})
	for _, d := range append(d.advisories, NewAdvisory(d.lang)) {
		vulns, err := d.DetectVulnerabilities(pkgName, pkgVer)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect vulnerabilities: %w", err)
		}
		for _, vuln := range vulns {
			if _, ok := uniqVulnIdMap[vuln.VulnerabilityID]; ok {
				continue
			}
			uniqVulnIdMap[vuln.VulnerabilityID] = struct{}{}
			detectedVulnerabilities = append(detectedVulnerabilities, vuln)
		}
	}

	return detectedVulnerabilities, nil
}

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
