package library

import (
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

const (
	scannerType = "unknown"
)

type Driver interface {
	Detect(string, *version.Version) ([]types.DetectedVulnerability, error)
	Type() string
}

type Factory interface {
	NewDriver(filename string) Driver
}

type DriverFactory struct{}

func (d DriverFactory) NewDriver(filename string) Driver {
	// TODO: use DI
	var scanner Driver
	switch filename {
	case "Gemfile.lock":
		scanner = NewScanner(ghsa.NewScanner(ecosystem.Rubygems), bundler.NewScanner())
	case "Cargo.lock":
		scanner = NewScanner(cargo.NewScanner())
	case "composer.lock":
		scanner = NewScanner(ghsa.NewScanner(ecosystem.Composer), composer.NewScanner())
	case "package-lock.json":
		scanner = NewScanner(ghsa.NewScanner(ecosystem.Npm), node.NewScanner(node.ScannerTypeNpm))
	case "yarn.lock":
		scanner = NewScanner(ghsa.NewScanner(ecosystem.Npm), node.NewScanner(node.ScannerTypeYarn))
	case "Pipfile.lock":
		scanner = NewScanner(ghsa.NewScanner(ecosystem.Pip), python.NewScanner(python.ScannerTypePipenv))
	case "poetry.lock":
		scanner = NewScanner(ghsa.NewScanner(ecosystem.Pip), python.NewScanner(python.ScannerTypePoetry))
	default:
		return nil
	}
	return scanner
}

type Scanner struct {
	drivers []Driver
	pos     Driver
}

func NewScanner(drivers ...Driver) *Scanner {
	return &Scanner{drivers: drivers}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error) {
	var detectedVulnerabilities []types.DetectedVulnerability
	uniqVulnIdMap := make(map[string]struct{})
	for _, d := range s.drivers {
		s.pos = d
		vulns, err := d.Detect(pkgName, pkgVer)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect error: %w", err)
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

func (s *Scanner) Type() string {
	if s.pos == nil {
		return scannerType
	}
	return s.pos.Type()
}
