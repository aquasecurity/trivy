package cloudformation

import (
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config"
	"github.com/deepfactor-io/trivy/pkg/misconf"
)

const (
	analyzerType = analyzer.TypeCloudFormation
	version      = 1
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzerType, newCloudFormationConfigAnalyzer)
}

// cloudFormationConfigAnalyzer is an analyzer for detecting misconfigurations in CloudFormation files.
// It embeds config.Analyzer so it can implement analyzer.PostAnalyzer.
type cloudFormationConfigAnalyzer struct {
	*config.Analyzer
}

func newCloudFormationConfigAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	a, err := config.NewAnalyzer(analyzerType, version, misconf.NewCloudFormationScanner, opts)
	if err != nil {
		return nil, err
	}
	return &cloudFormationConfigAnalyzer{Analyzer: a}, nil
}
