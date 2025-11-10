package dockerfile

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
)

const (
	version      = 1
	analyzerType = analyzer.TypeDockerfile
)

var requiredFiles = []string{"Dockerfile", "Containerfile"}

func init() {
	analyzer.RegisterPostAnalyzer(analyzerType, newDockerfileConfigAnalyzer)
}

// dockerConfigAnalyzer is an analyzer for detecting misconfigurations in Dockerfiles.
// It embeds config.Analyzer so it can implement analyzer.PostAnalyzer.
type dockerConfigAnalyzer struct {
	*config.Analyzer
}

func newDockerfileConfigAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	a, err := config.NewAnalyzer(analyzerType, version, detection.FileTypeDockerfile, opts)
	if err != nil {
		return nil, err
	}
	return &dockerConfigAnalyzer{Analyzer: a}, nil
}

// Required does a case-insensitive check for filePath and returns true if
// filePath equals/startsWith/hasExtension requiredFiles
// It overrides config.Analyzer.Required().
func (a *dockerConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	base := filepath.Base(filePath)
	ext := filepath.Ext(base)
	for _, file := range requiredFiles {
		if strings.EqualFold(base, file+ext) {
			return true
		}
		if strings.EqualFold(ext, "."+file) {
			return true
		}
	}

	return false
}
