package json

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var (
	requiredExt   = ".json"
	excludedFiles = []string{types.NpmPkgLock, types.NuGetPkgsLock, types.NuGetPkgsConfig}
)

type ConfigAnalyzer struct {
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		filePattern: filePattern,
	}
}

func (a ConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	b, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to read %s: %w", input.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Files: map[types.HandlerType][]types.File{
			// It will be passed to misconfig post handler
			types.MisconfPostHandler: {
				{
					Type:    types.JSON,
					Path:    input.FilePath,
					Content: b,
				},
			},
		},
	}, nil
}

func (a ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	if a.filePattern != nil && a.filePattern.MatchString(filePath) {
		return true
	}

	filename := filepath.Base(filePath)
	for _, excludedFile := range excludedFiles {
		if filename == excludedFile {
			return false
		}
	}

	return filepath.Ext(filePath) == requiredExt
}

func (ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJSON
}

func (ConfigAnalyzer) Version() int {
	return version
}
