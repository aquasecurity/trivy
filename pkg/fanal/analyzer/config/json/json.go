package json

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
)

const (
	analyzerType = analyzer.TypeJSON
	version      = 1
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzerType, newJSONConfigAnalyzer)
}

// jsonConfigAnalyzer analyzes JSON files
type jsonConfigAnalyzer struct {
	*config.Analyzer
}

func newJSONConfigAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	a, err := config.NewAnalyzer(analyzerType, version, detection.FileTypeJSON, opts)
	if err != nil {
		return nil, err
	}
	return &jsonConfigAnalyzer{Analyzer: a}, nil
}

func (*jsonConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Ext(filePath) == ".json"
}
