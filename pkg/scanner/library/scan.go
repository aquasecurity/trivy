package library

import (
	"os"
	"path/filepath"

	"github.com/knqyf263/fanal/analyzer"
	_ "github.com/knqyf263/fanal/analyzer/library/bundler"
	_ "github.com/knqyf263/fanal/analyzer/library/composer"
	_ "github.com/knqyf263/fanal/analyzer/library/npm"
	_ "github.com/knqyf263/fanal/analyzer/library/pipenv"
	"github.com/knqyf263/fanal/extractor"
	ptypes "github.com/knqyf263/go-dep-parser/pkg/types"
	"github.com/knqyf263/go-version"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/scanner/library/bundler"
	"github.com/knqyf263/trivy/pkg/scanner/library/composer"
	"github.com/knqyf263/trivy/pkg/scanner/library/npm"
	"github.com/knqyf263/trivy/pkg/scanner/library/pipenv"
	"github.com/knqyf263/trivy/pkg/types"
	"golang.org/x/xerrors"
)

type Scanner interface {
	UpdateDB() error
	ParseLockfile(*os.File) ([]ptypes.Library, error)
	Detect(string, *version.Version) ([]types.Vulnerability, error)
	Type() string
}

func NewScanner(filename string) Scanner {
	var scanner Scanner
	switch filename {
	case "Gemfile.lock":
		scanner = bundler.NewScanner()
	case "composer.lock":
		scanner = composer.NewScanner()
	case "package-lock.json":
		scanner = npm.NewScanner()
	case "Pipfile.lock":
		scanner = pipenv.NewScanner()
	default:
		return nil
	}
	return scanner
}

func Scan(files extractor.FileMap) (map[string][]types.Vulnerability, error) {
	results, err := analyzer.GetLibraries(files)
	if err != nil {
		return nil, xerrors.Errorf("failed to analyze libraries: %w", err)
	}

	vulnerabilities := map[string][]types.Vulnerability{}
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

		if len(vulns) != 0 {
			vulnerabilities[string(path)] = vulns
		}
	}
	return vulnerabilities, nil
}

func ScanFile(f *os.File) ([]types.Vulnerability, error) {
	scanner := NewScanner(f.Name())
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

func scan(scanner Scanner, pkgs []ptypes.Library) ([]types.Vulnerability, error) {
	log.Logger.Infof("Updating %s Security DB...", scanner.Type())
	err := scanner.UpdateDB()
	if err != nil {
		return nil, xerrors.Errorf("failed to update %s advisories: %w", scanner.Type(), err)
	}

	log.Logger.Infof("Detecting %s vulnerabilities...", scanner.Type())
	var vulnerabilities []types.Vulnerability
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
