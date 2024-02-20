package terraformplan

import (
	"os"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/misconf"
)

const (
	analyzerType = analyzer.TypeTerraformPlanSnapshot
	version      = 1
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzerType, newTerraformPlanSnapshotConfigAnalyzer)
}

// terraformPlanConfigAnalyzer is an analyzer for detecting misconfigurations in Terraform Plan files in snapshot format.
// It embeds config.Analyzer so it can implement analyzer.PostAnalyzer.
type terraformPlanConfigAnalyzer struct {
	*config.Analyzer
}

func newTerraformPlanSnapshotConfigAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	a, err := config.NewAnalyzer(analyzerType, version, misconf.NewTerraformPlanSnapshotScanner, opts)
	if err != nil {
		return nil, err
	}
	return &terraformPlanConfigAnalyzer{Analyzer: a}, nil
}

// TODO
// Required overrides config.Analyzer.Required() and checks if the given file is a Terraform file.
func (*terraformPlanConfigAnalyzer) Required(filePath string, fi os.FileInfo) bool {
	return true
}
