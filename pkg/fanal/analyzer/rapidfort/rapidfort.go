package rapidfort

import (
	"context"
	"os"
	"slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&curatedAnalyzer{})
}

const (
	analyzerVersion = 1
	curatedFilePath = "usr/share/rapidfort/curated.json"

	// CustomResourceType is the marker emitted when this analyzer finds the
	// RapidFort curated-image sentinel file. The RapidFort scanner provider
	// reads it to decide whether to switch to the RapidFort feed for the image.
	CustomResourceType = "rapidfort-curated"
)

var requiredFiles = []string{curatedFilePath}

// curatedAnalyzer detects RapidFort curated container images by the presence
// of /usr/share/rapidfort/curated.json in the image filesystem. Only presence
// is checked — the file contents are not read.
type curatedAnalyzer struct{}

func (a curatedAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return &analyzer.AnalysisResult{
		CustomResources: []types.CustomResource{
			{
				Type:     CustomResourceType,
				FilePath: input.FilePath,
			},
		},
	}, nil
}

func (a curatedAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a curatedAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRapidFortCurated
}

func (a curatedAnalyzer) Version() int {
	return analyzerVersion
}

// StaticPaths returns the fixed set of paths this analyzer cares about, so the
// fanal walker can short-circuit the Required() check for irrelevant files.
func (a curatedAnalyzer) StaticPaths() []string {
	return requiredFiles
}
