package library

import (
	"os"
	"path/filepath"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanner/library/bundler"
	"github.com/aquasecurity/trivy/pkg/scanner/library/cargo"
	"github.com/aquasecurity/trivy/pkg/scanner/library/composer"
	"github.com/aquasecurity/trivy/pkg/scanner/library/node"
	"github.com/aquasecurity/trivy/pkg/scanner/library/python"
	"github.com/knqyf263/go-version"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
)

type Scanner struct {
	detector DetectorOperation
}

func NewScanner(remoteURL, token string) Scanner {
	detector := NewDetector(remoteURL, token)
	return Scanner{detector: detector}
}

func (s Scanner) Scan(files extractor.FileMap) (map[string][]types.DetectedVulnerability, error) {
	results, err := analyzer.GetLibraries(files)
	if err != nil {
		return nil, xerrors.Errorf("failed to analyze libraries: %w", err)
	}

	vulnerabilities := map[string][]types.DetectedVulnerability{}
	for path, libs := range results {
		vulns, err := s.detector.Detect(string(path), libs)
		if err != nil {
			return nil, xerrors.Errorf("failed library scan: %w", err)
		}

		vulnerabilities[string(path)] = vulns
	}
	return vulnerabilities, nil
}

type ScannerOperation interface {
	ParseLockfile(*os.File) ([]ptypes.Library, error)
	Detect(string, *version.Version) ([]types.DetectedVulnerability, error)
	Type() string
}

func newScanner(filename string) ScannerOperation {
	var scanner ScannerOperation
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

func ScanFile(f *os.File) ([]types.DetectedVulnerability, error) {
	scanner := newScanner(filepath.Base(f.Name()))
	if scanner == nil {
		return nil, xerrors.New("unknown file type")
	}

	pkgs, err := scanner.ParseLockfile(f)
	if err != nil {
		return nil, err
	}

	vulns, err := detect(scanner, pkgs)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}
