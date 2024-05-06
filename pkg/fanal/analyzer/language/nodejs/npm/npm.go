package npm

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/npm"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
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
	logger        *log.Logger
	lockParser    language.Parser
	packageParser *packagejson.Parser
}

func newNpmLibraryAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &npmLibraryAnalyzer{
		logger:        log.WithPrefix("npm"),
		lockParser:    npm.NewParser(),
		packageParser: packagejson.NewParser(),
	}, nil
}

func (a npmLibraryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	// Parse package-lock.json
	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.NpmPkgLock
	}

	var apps []types.Application
	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		// Find all licenses from package.json files under node_modules dirs
		licenses, err := a.findLicenses(input.FS, filePath)
		if err != nil {
			a.logger.Error("Unable to collect licenses", log.Err(err))
			licenses = make(map[string][]string)
		}

		app, err := a.parseNpmPkgLock(input.FS, filePath)
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

func (a npmLibraryAnalyzer) parseNpmPkgLock(fsys fs.FS, filePath string) (*types.Application, error) {
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
	return language.Parse(types.Npm, filePath, file, a.lockParser)
}

func (a npmLibraryAnalyzer) findLicenses(fsys fs.FS, lockPath string) (map[string][]string, error) {
	dir := path.Dir(lockPath)
	root := path.Join(dir, "node_modules")
	if _, err := fs.Stat(fsys, root); errors.Is(err, fs.ErrNotExist) {
		a.logger.Info(`To collect the license information of packages, "npm install" needs to be performed beforehand`,
			log.String("dir", root))
		return nil, nil
	}

	// Parse package.json
	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.NpmPkg
	}

	// Traverse node_modules dir and find licenses
	// Note that fs.FS is always slashed regardless of the platform,
	// and path.Join should be used rather than filepath.Join.
	licenses := make(map[string][]string)
	err := fsutils.WalkDir(fsys, root, required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		pkg, err := a.packageParser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", filePath, err)
		}

		licenses[pkg.ID] = pkg.Licenses
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}
	return licenses, nil
}
