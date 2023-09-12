package terraform

import (
	"os"

	"github.com/aquasecurity/defsec/pkg/detection"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/misconf"
)

const (
	analyzerType = analyzer.TypeTerraform
	version      = 1
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzerType, newTerraformConfigAnalyzer)
}

// terraformConfigAnalyzer is an analyzer for detecting misconfigurations in Terraform files.
// It embeds config.Analyzer so it can implement analyzer.PostAnalyzer.
type terraformConfigAnalyzer struct {
	*config.Analyzer
}

func newTerraformConfigAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	a, err := config.NewAnalyzer(analyzerType, version, misconf.NewTerraformScanner, opts)
	if err != nil {
		return nil, err
	}
	return &terraformConfigAnalyzer{Analyzer: a}, nil
}

// Required overrides config.Analyzer.Required() and checks if the given file is a Terraform file.
func (*terraformConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return detection.IsTerraformFile(filePath)
}
