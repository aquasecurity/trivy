package ansible

import (
	"os"
	"path/filepath"
	"slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
)

const (
	version      = 1
	analyzerType = analyzer.TypeAnsible
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzerType, newAnsibleConfigAnalyzer)
}

type ansibleConfigAnalyzer struct {
	*config.Analyzer
}

func newAnsibleConfigAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	a, err := config.NewAnalyzer(analyzerType, version, detection.FileTypeAnsible, opts)
	if err != nil {
		return nil, err
	}
	return &ansibleConfigAnalyzer{Analyzer: a}, nil
}

func (a *ansibleConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == "ansible.cfg" ||
		slices.Contains([]string{"", ".yml", ".yaml", ".json", ".ini"}, filepath.Ext(filePath))
}
