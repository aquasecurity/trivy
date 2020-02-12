package library

import (
	"time"

	detector "github.com/aquasecurity/trivy/pkg/detector/library"

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
	detector detector.Operation
}

func NewScanner(detector detector.Operation) Scanner {
	return Scanner{detector: detector}
}

func (s Scanner) Scan(imageName string, created time.Time, files extractor.FileMap) (map[string][]types.DetectedVulnerability, error) {
	results, err := analyzer.GetLibraries(files)
	if err != nil {
		return nil, xerrors.Errorf("failed to analyze libraries: %w", err)
	}

	vulnerabilities := map[string][]types.DetectedVulnerability{}
	for path, libs := range results {
		vulns, err := s.detector.Detect(imageName, string(path), created, libs)
		if err != nil {
			return nil, xerrors.Errorf("failed library scan: %w", err)
		}

		vulnerabilities[string(path)] = vulns
	}
	return vulnerabilities, nil
}
