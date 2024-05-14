package bundler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/ruby/bundler"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&bundlerLibraryAnalyzer{})
}

const version = 1

type bundlerLibraryAnalyzer struct{}

func (a bundlerLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.Bundler, input.FilePath, input.Content, bundler.NewParser())
	if err != nil {
		return nil, fmt.Errorf("unable to parse Gemfile.lock: %w", err)
	}
	return res, nil
}

func (a bundlerLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return fileName == types.GemfileLock
}

func (a bundlerLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeBundler
}

func (a bundlerLibraryAnalyzer) Version() int {
	return version
}
