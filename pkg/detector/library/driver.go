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
)

type driver interface {
	Detect(string, *version.Version) ([]types.DetectedVulnerability, error)
	Type() string
}

type Factory interface {
	NewDriver(filename string) driver
}

type DriverFactory struct{}

func (d DriverFactory) NewDriver(filename string) driver {
	// TODO: use DI
	var scanner *Scanner
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
