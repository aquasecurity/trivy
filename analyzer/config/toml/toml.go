package toml

import (
	"context"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/BurntSushi/toml"
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredExts = []string{".toml"}

type ConfigAnalyzer struct {
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		filePattern: filePattern,
	}
}

func (a ConfigAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if _, err := toml.NewDecoder(target.Content).Decode(&parsed); err != nil {
		return nil, xerrors.Errorf("unable to decode TOML (%s): %w", target.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Configs: []types.Config{
			{
				Type:     types.TOML,
				FilePath: target.FilePath,
				Content:  parsed,
			},
		},
	}, nil
}

func (a ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	if a.filePattern != nil && a.filePattern.MatchString(filePath) {
		return true
	}

	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeTOML
}

func (ConfigAnalyzer) Version() int {
	return version
}
