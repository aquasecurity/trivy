package terraform

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const version = 1

var requiredExts = []string{".tf", ".tf.json"}

type ConfigAnalyzer struct {
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		filePattern: filePattern,
	}
}

// Analyze returns a name of Terraform file
func (a ConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	b, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("read error (%s): %w", input.FilePath, err)
	}
	return &analyzer.AnalysisResult{
		Files: map[types.HandlerType][]types.File{
			// It will be passed to misconf post handler
			types.MisconfPostHandler: {
				{
					Type:    types.Terraform,
					Path:    input.FilePath,
					Content: b,
				},
			},
		},
	}, nil
}

func (a ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// with --file-patterns
	if a.filePattern != nil && a.filePattern.MatchString(filePath) {
		return true
	}

	for _, acceptable := range requiredExts {
		if strings.HasSuffix(strings.ToLower(filePath), acceptable) {
			return true
		}
	}
	return false
}

func (ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeTerraform
}

func (ConfigAnalyzer) Version() int {
	return version
}
