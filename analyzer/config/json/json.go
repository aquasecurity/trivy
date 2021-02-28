package json

import (
	"os"
	"path/filepath"

	"github.com/open-policy-agent/conftest/parser/json"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&jsonConfigAnalyzer{
		parser: &json.Parser{},
	})
}

const version = 1

var requiredExts = []string{".json"}

type jsonConfigAnalyzer struct {
	parser *json.Parser
}

func (a jsonConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := a.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse JSON (%s): %w", target.FilePath, err)
	}
	return &analyzer.AnalysisResult{
		Configs: []types.Config{{
			Type:     config.JSON,
			FilePath: target.FilePath,
			Content:  parsed,
		}},
	}, nil
}

func (a jsonConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (a jsonConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJSON
}

func (a jsonConfigAnalyzer) Version() int {
	return version
}
