package dockerfile

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredFiles = []string{"Dockerfile", "Containerfile"}

type ConfigAnalyzer struct {
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		filePattern: filePattern,
	}
}

func (s ConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
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
func (s ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	if s.filePattern != nil && s.filePattern.MatchString(filePath) {
		return true
	}

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

func (s ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDockerfile
}

func (s ConfigAnalyzer) Version() int {
	return version
}
