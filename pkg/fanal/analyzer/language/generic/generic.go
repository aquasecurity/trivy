package generic

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/generic"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(types.GenericDeps, newGenericAnalyzer)
}

const (
	version = 1
)

type genericLibraryAnalyzer struct {
	logger *log.Logger
	parser language.Parser
}

func newGenericAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &genericLibraryAnalyzer{
		logger: log.WithPrefix("generic"),
		parser: generic.NewParser(),
	}, nil
}

func (a genericLibraryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	// Parse dependencies.json files
	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.GenericDeps || input.FilePatterns.Match(path)
	}

	var apps []types.Application
	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		app, err := a.parseGenericFile(input.FS, filePath)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("dependencies.json walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a genericLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return fileName == types.GenericDeps
}

func (a genericLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.Type(types.GenericDeps)
}

func (a genericLibraryAnalyzer) Version() int {
	return version
}

func (a genericLibraryAnalyzer) parseGenericFile(fsys fs.FS, filePath string) (*types.Application, error) {
	f, err := fsys.Open(filePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	file, ok := f.(xio.ReadSeekCloserAt)
	if !ok {
		return nil, xerrors.Errorf("type assertion error: %w", err)
	}

	// parse generic.json file
	return language.Parse(types.Generic, filePath, file, a.parser)
}
