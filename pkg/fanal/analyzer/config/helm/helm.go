package helm

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
)

const (
	analyzerType = analyzer.TypeHelm
	version      = 1
	maxTarSize   = 209_715_200 // 200MB
)

var acceptedExts = []string{".tpl", ".json", ".yml", ".yaml", ".tar", ".tgz", ".tar.gz"}

func init() {
	analyzer.RegisterPostAnalyzer(analyzerType, newHelmConfigAnalyzer)
}

// helmConfigAnalyzer is an analyzer for detecting misconfigurations in Helm charts.
// It embeds config.Analyzer so it can implement analyzer.PostAnalyzer.
type helmConfigAnalyzer struct {
	*config.Analyzer
}

func newHelmConfigAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	a, err := config.NewAnalyzer(analyzerType, version, detection.FileTypeHelm, opts)
	if err != nil {
		return nil, err
	}
	return &helmConfigAnalyzer{Analyzer: a}, nil
}

// Required overrides config.Analyzer.Required() and checks if the given file is a Helm chart.
func (*helmConfigAnalyzer) Required(filePath string, info os.FileInfo) bool {
	if info.Size() > maxTarSize {
		// tarball is too big to be Helm chart - move on
		return false
	}

	for _, acceptable := range acceptedExts {
		if strings.HasSuffix(strings.ToLower(filePath), acceptable) {
			return true
		}
	}

	name := filepath.Base(filePath)
	for _, acceptable := range []string{"Chart.yaml", ".helmignore"} {
		if strings.EqualFold(name, acceptable) {
			return true
		}
	}

	return false
}
