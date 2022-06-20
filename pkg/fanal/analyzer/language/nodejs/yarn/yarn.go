package yarn

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/yarn"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&yarnLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{types.YarnLock}

type yarnLibraryAnalyzer struct{}

func (a yarnLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.Yarn, input.FilePath, input.Content, yarn.NewParser())
	if err != nil {
		return nil, xerrors.Errorf("unable to parse yarn.lock: %w", err)
	}
	return res, nil
}

func (a yarnLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a yarnLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeYarn
}

func (a yarnLibraryAnalyzer) Version() int {
	return version
}
