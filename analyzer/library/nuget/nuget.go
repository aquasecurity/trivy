package nuget

import (
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/nuget"
)

func init() {
	analyzer.RegisterAnalyzer(&nugetLibraryAnalyzer{})
}

var requiredFiles = []string{"packages.lock.json"}

type nugetLibraryAnalyzer struct{}

func (a nugetLibraryAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	ret, err := library.Analyze(content, nuget.Parse)
	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("unable to parse packages.lock.json: %w", err)
	}
	return ret, nil
}

func (a nugetLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a nugetLibraryAnalyzer) Name() string {
	return library.NuGet
}
