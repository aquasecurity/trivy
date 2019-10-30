package library

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"
	"github.com/aquasecurity/fanal/extractor"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/library/bundler"
	"github.com/aquasecurity/trivy/pkg/scanner/library/cargo"
	"github.com/aquasecurity/trivy/pkg/scanner/library/composer"
	"github.com/aquasecurity/trivy/pkg/scanner/library/node"
	"github.com/aquasecurity/trivy/pkg/scanner/library/python"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/knqyf263/go-version"
	"golang.org/x/xerrors"
)

type Scanner interface {
	ParseLockfile(*os.File) ([]ptypes.Library, error)
	Detect(string, *version.Version) ([]types.DetectedVulnerability, error)
	Type() string
}

func NewScanner(filename string) Scanner {
	var scanner Scanner
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

func Scan(files extractor.FileMap, scanOptions types.ScanOptions) (map[string][]types.DetectedVulnerability, error) {
	results, err := analyzer.GetLibraries(files)
	if err != nil {
		return nil, xerrors.Errorf("failed to analyze libraries: %w", err)
	}

	vulnerabilities := map[string][]types.DetectedVulnerability{}
	for path, pkgs := range results {
		log.Logger.Debugf("Detecting library vulnerabilities, path: %s", path)
		scanner := NewScanner(filepath.Base(string(path)))
		if scanner == nil {
			return nil, xerrors.New("unknown file type")
		}

		vulns, err := scan(scanner, pkgs)
		if err != nil {
			return nil, xerrors.Errorf("failed to scan %s vulnerabilities: %w", scanner.Type(), err)
		}

		vulnerabilities[string(path)] = vulns
	}
	return vulnerabilities, nil
}

func ScanFile(f *os.File) ([]types.DetectedVulnerability, error) {
	scanner := NewScanner(filepath.Base(f.Name()))
	if scanner == nil {
		return nil, xerrors.New("unknown file type")
	}

	pkgs, err := scanner.ParseLockfile(f)
	if err != nil {
		return nil, err
	}

	vulns, err := scan(scanner, pkgs)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

func scan(scanner Scanner, pkgs []ptypes.Library) ([]types.DetectedVulnerability, error) {
	log.Logger.Infof("Detecting %s vulnerabilities...", scanner.Type())
	var vulnerabilities []types.DetectedVulnerability
	for _, pkg := range pkgs {
		v, err := version.NewVersion(pkg.Version)
		if err != nil {
			log.Logger.Debug(err)
			continue
		}

		vulns, err := scanner.Detect(pkg.Name, v)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", scanner.Type(), err)
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}
