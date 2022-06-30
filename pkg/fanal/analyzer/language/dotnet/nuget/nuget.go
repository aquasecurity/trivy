package nuget

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/exp/slices"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/nuget/config"
	"github.com/aquasecurity/go-dep-parser/pkg/nuget/lock"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
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
	parser := lock.NewParser()

	targetFile := filepath.Base(input.FilePath)
	if targetFile == configFile {
		parser = config.NewParser()
	}

	res, err := language.Analyze(types.NuGet, input.FilePath, input.Content, parser)
	if err != nil {
		return nil, xerrors.Errorf("NuGet analysis error: %w", err)
	}
	return res, nil
}

func (a nugetLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a nugetLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNuget
}

func (a nugetLibraryAnalyzer) Version() int {
	return version
}
