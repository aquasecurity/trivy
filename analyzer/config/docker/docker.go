package docker

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/conftest/parser/docker"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&dockerConfigAnalyzer{
		parser: &docker.Parser{},
	})
}

const version = 1

var requiredFile = "Dockerfile"

type dockerConfigAnalyzer struct {
	parser *docker.Parser
}

func (a dockerConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := a.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse Dockerfile (%s): %w", target.FilePath, err)
	}
	return &analyzer.AnalysisResult{
		Configs: []types.Config{{
			Type:     config.Dockerfile,
			FilePath: target.FilePath,
			Content:  parsed,
		}},
	}, nil
}

// Required does a case-insensitive check for filePath and returns true if
// filePath equals/startsWith/hasExtension requiredFile
func (a dockerConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
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

func (a dockerConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDockerfile
}

func (a dockerConfigAnalyzer) Version() int {
	return version
}
