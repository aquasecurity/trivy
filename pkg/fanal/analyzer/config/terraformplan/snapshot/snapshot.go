package terraformplan

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
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
	a, err := config.NewAnalyzer(analyzerType, version, detection.FileTypeTerraformPlanSnapshot, opts)
	if err != nil {
		return nil, err
	}
	return &terraformPlanConfigAnalyzer{Analyzer: a}, nil
}

func (*terraformPlanConfigAnalyzer) Required(filePath string, fi os.FileInfo) bool {
	return filepath.Ext(filePath) == ".tfplan" || filepath.Base(filePath) == "tfplan"
}
