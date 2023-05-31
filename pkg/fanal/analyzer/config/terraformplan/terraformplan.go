package terraformplan

import (
	"os"
	"path/filepath"

	"k8s.io/utils/strings/slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/misconf"
)

const (
	analyzerType = analyzer.TypeTerraformPlan
	version      = 1
)

var requiredExts = []string{
	".json",
}

func init() {
	analyzer.RegisterPostAnalyzer(analyzerType, newTerraformPlanConfigAnalyzer)
}

// terraformPlanConfigAnalyzer is an analyzer for detecting misconfigurations in Terraform files.
// It embeds config.Analyzer so it can implement analyzer.PostAnalyzer.
type terraformPlanConfigAnalyzer struct {
	*config.Analyzer
}

func newTerraformPlanConfigAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	a, err := config.NewAnalyzer(analyzerType, version, misconf.NewTerraformPlanScanner, opts)
	if err != nil {
		return nil, err
	}
	return &terraformPlanConfigAnalyzer{Analyzer: a}, nil
}

// Required overrides config.Analyzer.Required() and checks if the given file is a Terraform file.
func (*terraformPlanConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredExts, filepath.Ext(filePath))
}
