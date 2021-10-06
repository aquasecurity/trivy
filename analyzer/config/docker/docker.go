package docker

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/config/parser/dockerfile"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredFile = "Dockerfile"

type ConfigAnalyzer struct {
	parser      *dockerfile.Parser
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		parser:      &dockerfile.Parser{},
		filePattern: filePattern,
	}
}

func (s ConfigAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	parsed, err := s.parser.Parse(target.Content)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse Dockerfile (%s): %w", target.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Configs: []types.Config{
			{
				Type:     types.Dockerfile,
				FilePath: target.FilePath,
				Content:  parsed,
			},
		},
	}, nil
}

// Required does a case-insensitive check for filePath and returns true if
// filePath equals/startsWith/hasExtension requiredFile
func (s ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	if s.filePattern != nil && s.filePattern.MatchString(filePath) {
		return true
	}

	base := filepath.Base(filePath)
	ext := filepath.Ext(base)
	if strings.EqualFold(base, requiredFile+ext) {
		return true
	}
	if strings.EqualFold(ext, "."+requiredFile) {
		return true
	}

	return false
}

func (s ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDockerfile
}

func (s ConfigAnalyzer) Version() int {
	return version
}
