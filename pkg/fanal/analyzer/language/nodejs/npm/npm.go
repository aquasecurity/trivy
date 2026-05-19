package npm

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/npm"
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
	analyzer.RegisterPostAnalyzer(analyzer.TypeNpmPkgLock, newNpmLibraryAnalyzer)
}

const (
	version = 1
)

type npmLibraryAnalyzer struct {
	logger     *log.Logger
	lockParser language.Parser
	license    *license.License
}

func newNpmLibraryAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &npmLibraryAnalyzer{
		logger:     log.WithPrefix("npm"),
		lockParser: npm.NewParser(),
		license:    license.NewLicense(opt.LicenseScannerOption.ClassifierConfidenceLevel),
	}, nil
}

func (a npmLibraryAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	// Parse package-lock.json
	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.NpmPkgLock || input.FilePatterns.Match(path)
	}

	var apps []types.Application
	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, _ io.Reader) error {
		// Find all licenses from package.json files under node_modules dirs
		licenses, err := a.license.Traverse(input.FS, path.Join(path.Dir(filePath), "node_modules"))
		if err != nil {
			a.logger.Error("Unable to collect licenses", log.Err(err))
			licenses = make(map[string][]string)
		}

		app, err := a.parseNpmPkgLock(ctx, input.FS, filePath)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Fill licenses from package.json only if not present in lock file
		for i, pkg := range app.Packages {
			if len(pkg.Licenses) == 0 {
				if ll, ok := licenses[pkg.ID]; ok {
					app.Packages[i].Licenses = ll
				}
			}
		}

		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("package-lock.json/package.json walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a npmLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	// Don't save package-lock.json from the `node_modules` directory to avoid duplication and mistakes.
	if fileName == types.NpmPkgLock && !xpath.Contains(filePath, "node_modules") {
		return true
	}

	// Save package.json files only from the `node_modules` directory.
	// Required to search for licenses.
	if fileName == types.NpmPkg && xpath.Contains(filePath, "node_modules") {
		return true
	}
	return false
}

func (a npmLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNpmPkgLock
}

func (a npmLibraryAnalyzer) Version() int {
	return version
}

func (a npmLibraryAnalyzer) parseNpmPkgLock(ctx context.Context, fsys fs.FS, filePath string) (*types.Application, error) {
	f, err := fsys.Open(filePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	file, ok := f.(xio.ReadSeekCloserAt)
	if !ok {
		return nil, xerrors.Errorf("type assertion error: %w", err)
	}

	// parse package-lock.json file
	return language.Parse(ctx, types.Npm, filePath, file, a.lockParser)
}
