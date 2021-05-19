package json

import (
	"os"
	"path/filepath"
	"regexp"

	"github.com/open-policy-agent/conftest/parser/json"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredExts = []string{".json"}

type ConfigAnalyzer struct {
	parser      *json.Parser
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		parser:      &json.Parser{},
		filePattern: filePattern,
	}
}

func (a ConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := a.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse JSON (%s): %w", target.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Configs: []types.Config{
			{
				Type:     types.JSON,
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
	return analyzer.TypeJSON
}

func (ConfigAnalyzer) Version() int {
	return version
}
