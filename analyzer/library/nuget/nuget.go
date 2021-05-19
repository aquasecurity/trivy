package nuget

import (
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/nuget"
)

func init() {
	analyzer.RegisterAnalyzer(&nugetLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{"packages.lock.json"}

type nugetLibraryAnalyzer struct{}

func (a nugetLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(types.NuGet, target.FilePath, target.Content, nuget.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse packages.lock.json: %w", err)
	}
	return res, nil
}

func (a nugetLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a nugetLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNuget
}

func (a nugetLibraryAnalyzer) Version() int {
	return version
}
