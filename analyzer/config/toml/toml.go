package toml

import (
	"os"
	"path/filepath"

	"github.com/open-policy-agent/conftest/parser/toml"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&tomlConfigAnalyzer{
		parser: &toml.Parser{},
	})
}

const version = 1

var requiredExts = []string{".toml"}

type tomlConfigAnalyzer struct {
	parser *toml.Parser
}

func (a tomlConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := a.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse TOML (%s): %w", target.FilePath, err)
	}
	return &analyzer.AnalysisResult{
		Configs: []types.Config{{
			Type:     config.TOML,
			FilePath: target.FilePath,
			Content:  parsed,
		}},
	}, nil
}

func (a tomlConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (a tomlConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeTOML
}

func (a tomlConfigAnalyzer) Version() int {
	return version
}
