package yarn

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/go-dep-parser/pkg/yarn"

	"github.com/aquasecurity/fanal/utils"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&yarnLibraryAnalyzer{})
}

var requiredFiles = []string{"yarn.lock"}

type yarnLibraryAnalyzer struct{}

func (a yarnLibraryAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	ret, err := library.Analyze(content, yarn.Parse)
	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("unable to parse yarn.lock: %w", err)
	}
	return ret, nil
}

func (a yarnLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a yarnLibraryAnalyzer) Name() string {
	return library.Yarn
}
