package yaml

import (
	"os"
	"path/filepath"

	"github.com/open-policy-agent/conftest/parser/yaml"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&yamlConfigAnalyzer{
		parser: &yaml.Parser{},
	})
}

const version = 1

var requiredExts = []string{".yaml", ".yml"}

type yamlConfigAnalyzer struct {
	parser *yaml.Parser
}

func (a yamlConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := a.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse YAML (%s): %w", target.FilePath, err)
	}
	return &analyzer.AnalysisResult{
		Configs: []types.Config{{
			Type:     config.YAML,
			FilePath: target.FilePath,
			Content:  parsed,
		}},
	}, nil
}

func (a yamlConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (a yamlConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeYaml
}

func (a yamlConfigAnalyzer) Version() int {
	return version
}
