package bundler

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

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
		return nil, xerrors.Errorf("unable to parse Gemfile.lock: %w", err)
	}
	return res, nil
}

func (a bundlerLibraryAnalyzer) Required(filePath string, fileInfo os.FileInfo) bool {
	others := os.Getenv("RUBY")
	if size := fileInfo.Size(); size > 10485760 && others != "" { // 10MB
		log.WithPrefix("npm yarn oss").Warn("The size of the scanned file is too large. It is recommended to use `--skip-files` for this file to avoid high memory consumption.", log.Int64("size (MB)", size/1048576))
		return false
	}
	fileName := filepath.Base(filePath)
	return fileName == types.GemfileLock
}

func (a bundlerLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeBundler
}

func (a bundlerLibraryAnalyzer) Version() int {
	return version
}
