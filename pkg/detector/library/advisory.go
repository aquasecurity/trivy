package library

import (
	"github.com/aquasecurity/fanal/analyzer/library"
	ecosystem "github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy/pkg/detector/library/bundler"
	"github.com/aquasecurity/trivy/pkg/detector/library/cargo"
	"github.com/aquasecurity/trivy/pkg/detector/library/composer"
	"github.com/aquasecurity/trivy/pkg/detector/library/ghsa"
	"github.com/aquasecurity/trivy/pkg/detector/library/node"
	"github.com/aquasecurity/trivy/pkg/detector/library/python"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/knqyf263/go-version"
	"golang.org/x/xerrors"
)

type Driver struct {
	pkgManager string
	advisories []advisory
}

type advisory interface {
	DetectVulnerabilities(string, *version.Version) ([]types.DetectedVulnerability, error)
}

func NewDriver(p string, advisories ...advisory) Driver {
	return Driver{pkgManager: p, advisories: advisories}
}

func NewBundlerDriver() Driver {
	return NewDriver(library.Bundler, ghsa.NewAdvisory(ecosystem.Rubygems), bundler.NewAdvisory())
}

func NewComposerDriver() Driver {
	return NewDriver(library.Composer, ghsa.NewAdvisory(ecosystem.Composer), composer.NewAdvisory())
}

func NewCargoDriver() Driver {
	return NewDriver(library.Cargo, cargo.NewAdvisory())
}

func NewNpmDriver() Driver {
	return NewDriver(library.Npm, ghsa.NewAdvisory(ecosystem.Npm), node.NewAdvisory())
}

func NewYarnDriver() Driver {
	return NewDriver(library.Yarn, ghsa.NewAdvisory(ecosystem.Npm), node.NewAdvisory())
}

func NewPipenvDriver() Driver {
	return NewDriver(library.Pipenv, ghsa.NewAdvisory(ecosystem.Pip), python.NewAdvisory())
}

func NewPoetryDriver() Driver {
	return NewDriver(library.Poetry, ghsa.NewAdvisory(ecosystem.Pip), python.NewAdvisory())
}

func (driver *Driver) Detect(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error) {
	var detectedVulnerabilities []types.DetectedVulnerability
	uniqVulnIdMap := make(map[string]struct{})
	for _, d := range driver.advisories {
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
	return d.pkgManager
}
