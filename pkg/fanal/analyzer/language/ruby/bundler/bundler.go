package bundler

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/ruby/bundler"
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
		return nil, xerrors.Errorf("unable to parse Gemfile.lock: %w", err)
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
