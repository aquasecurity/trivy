package pip

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pip"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePip, newPipLibraryAnalyzer)
}

const version = 1

type pipLibraryAnalyzer struct{}

func newPipLibraryAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return pipLibraryAnalyzer{}, nil
}

func (a pipLibraryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application
	// We only saved the `requirement.txt` files
	required := func(_ string, _ fs.DirEntry) bool {
		return true
	}

	if err := fsutils.WalkDir(input.FS, ".", required, func(pathPath string, d fs.DirEntry, r io.Reader) error {
		app, err := language.Parse(types.Pip, pathPath, r, pip.NewParser())
		if err != nil {
			return xerrors.Errorf("unable to parse requirements.txt: %w", err)
		}

		if app == nil {
			return nil
		}

		// TODO insert licenses

		apps = append(apps, *app)
		return nil
	}); err != nil {
		return nil, xerrors.Errorf("pip walt error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a pipLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return fileName == types.PipRequirements
}

func (a pipLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePip
}

func (a pipLibraryAnalyzer) Version() int {
	return version
}
