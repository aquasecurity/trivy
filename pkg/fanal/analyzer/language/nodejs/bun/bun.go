package bun

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/bun"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/license"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xpath "github.com/aquasecurity/trivy/pkg/x/path"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeBun, newBunLibraryAnalyzer)
}

const (
	version = 1
)

type bunLibraryAnalyzer struct {
	logger     *log.Logger
	lockParser language.Parser
	license    *license.License
}

func newBunLibraryAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &bunLibraryAnalyzer{
		logger:     log.WithPrefix("bun"),
		lockParser: bun.NewParser(),
		license:    license.NewLicense(opt.LicenseScannerOption.ClassifierConfidenceLevel),
	}, nil
}

func (a bunLibraryAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	// Parse bun.lock
	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.BunLock || input.FilePatterns.Match(path)
	}

	var apps []types.Application
	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, _ io.Reader) error {
		// Find all licenses from package.json files under node_modules dirs
		licenses, err := a.license.Traverse(input.FS, path.Join(path.Dir(filePath), "node_modules"))
		if err != nil {
			a.logger.Error("Unable to collect licenses", log.Err(err))
			licenses = make(map[string][]string)
		}

		app, err := a.parseBunLock(ctx, input.FS, filePath)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Fill licenses
		for i, lib := range app.Packages {
			if ll, ok := licenses[lib.ID]; ok {
				app.Packages[i].Licenses = ll
			}
		}
		sort.Sort(app.Packages)
		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("bun.lock/package.json walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a bunLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	if fileName == types.BunLock {
		return true
	}

	// Save package.json files only from the `node_modules` directory.
	// Required to search for licenses.
	if fileName == types.NpmPkg && xpath.Contains(filePath, "node_modules") {
		return true
	}
	return false
}

func (a bunLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeBun
}

func (a bunLibraryAnalyzer) Version() int {
	return version
}

func (a bunLibraryAnalyzer) parseBunLock(ctx context.Context, fsys fs.FS, filePath string) (*types.Application, error) {
	f, err := fsys.Open(filePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	file, ok := f.(xio.ReadSeekCloserAt)
	if !ok {
		return nil, xerrors.New("type assertion error: file does not implement xio.ReadSeekCloserAt")
	}

	// parse bun.lock
	return language.Parse(ctx, types.Bun, filePath, file, a.lockParser)
}
