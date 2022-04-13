package nuget

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/nuget/config"
	"github.com/aquasecurity/go-dep-parser/pkg/nuget/lock"
)

func init() {
	analyzer.RegisterAnalyzer(&nugetLibraryAnalyzer{})
}

const (
	version    = 2
	lockFile   = types.NuGetPkgsLock
	configFile = types.NuGetPkgsConfig
)

var requiredFiles = []string{lockFile, configFile}

type nugetLibraryAnalyzer struct{}

func (a nugetLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// Set the default parser
	parser := lock.Parse

	targetFile := filepath.Base(input.FilePath)
	if targetFile == configFile {
		parser = config.Parse
	}

	res, err := language.Analyze(types.NuGet, input.FilePath, input.Content, parser)
	if err != nil {
		return nil, xerrors.Errorf("NuGet analysis error: %w", err)
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
