package dockerfile

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&dockerConfigAnalyzer{})
}

const version = 1

var requiredFiles = []string{"Dockerfile", "Containerfile"}

type dockerConfigAnalyzer struct{}

func (s dockerConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	b, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to read %s: %w", input.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Files: map[types.HandlerType][]types.File{
			// It will be passed to misconfig post handler
			types.MisconfPostHandler: {
				{
					Type:    types.Dockerfile,
					Path:    input.FilePath,
					Content: b,
				},
			},
		},
	}, nil
}

// Required does a case-insensitive check for filePath and returns true if
// filePath equals/startsWith/hasExtension requiredFiles
func (s dockerConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
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

func (s dockerConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDockerfile
}

func (s dockerConfigAnalyzer) Version() int {
	return version
}
