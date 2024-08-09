package k8s

import (
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
)

const (
	analyzerType = analyzer.TypeKubernetes
	version      = 1
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzerType, newKubernetesConfigAnalyzer)
}

// kubernetesConfigAnalyzer is an analyzer for detecting misconfigurations in Kubernetes config files.
// It embeds config.Analyzer so it can implement analyzer.PostAnalyzer.
type kubernetesConfigAnalyzer struct {
	*config.Analyzer
}

func newKubernetesConfigAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	a, err := config.NewAnalyzer(analyzerType, version, detection.FileTypeKubernetes, opts)
	if err != nil {
		return nil, err
	}
	return &kubernetesConfigAnalyzer{Analyzer: a}, nil
}
