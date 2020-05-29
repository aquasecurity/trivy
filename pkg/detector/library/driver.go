package library

import (
	ecosystem "github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy/pkg/detector/library/bundler"
	"github.com/aquasecurity/trivy/pkg/detector/library/cargo"
	"github.com/aquasecurity/trivy/pkg/detector/library/composer"
	"github.com/aquasecurity/trivy/pkg/detector/library/ghsa"
	"github.com/aquasecurity/trivy/pkg/detector/library/node"
	"github.com/aquasecurity/trivy/pkg/detector/library/python"
)

type Factory interface {
	NewDriver(filename string) Driver
}

type DriverFactory struct{}

func (d DriverFactory) NewDriver(filename string) Driver {
	// TODO: use DI
	var driver Driver
	switch filename {
	case "Gemfile.lock":
		driver = NewDriver(Bundler, ghsa.NewAdvisory(ecosystem.Rubygems), bundler.NewAdvisory())
	case "Cargo.lock":
		driver = NewDriver(Cargo, cargo.NewAdvisory())
	case "composer.lock":
		driver = NewDriver(Composer, ghsa.NewAdvisory(ecosystem.Composer), composer.NewAdvisory())
	case "package-lock.json":
		driver = NewDriver(Npm, ghsa.NewAdvisory(ecosystem.Npm), node.NewAdvisory())
	case "yarn.lock":
		driver = NewDriver(Yarn, ghsa.NewAdvisory(ecosystem.Npm), node.NewAdvisory())
	case "Pipfile.lock":
		driver = NewDriver(Pipenv, ghsa.NewAdvisory(ecosystem.Pip), python.NewAdvisory())
	case "poetry.lock":
		driver = NewDriver(Poetry, ghsa.NewAdvisory(ecosystem.Pip), python.NewAdvisory())
	default:
		return nil
	}
	return driver
}
