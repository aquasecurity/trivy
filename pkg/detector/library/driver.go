package library

import (
	"os"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/bundler"
	"github.com/aquasecurity/trivy/pkg/detector/library/cargo"
	"github.com/aquasecurity/trivy/pkg/detector/library/composer"
	"github.com/aquasecurity/trivy/pkg/detector/library/node"
	"github.com/aquasecurity/trivy/pkg/detector/library/python"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/knqyf263/go-version"
)

type Driver interface {
	ParseLockfile(*os.File) ([]ptypes.Library, error)
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
		scanner = bundler.NewScanner()
	case "Cargo.lock":
		scanner = cargo.NewScanner()
	case "composer.lock":
		scanner = composer.NewScanner()
	case "package-lock.json":
		scanner = node.NewScanner(node.ScannerTypeNpm)
	case "yarn.lock":
		scanner = node.NewScanner(node.ScannerTypeYarn)
	case "Pipfile.lock":
		scanner = python.NewScanner(python.ScannerTypePipenv)
	case "poetry.lock":
		scanner = python.NewScanner(python.ScannerTypePoetry)
	default:
		return nil
	}
	return scanner
}
