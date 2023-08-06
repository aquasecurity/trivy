package npm

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/npm"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xpath "github.com/aquasecurity/trivy/pkg/x/path"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeNpmPkgLock, newNpmLibraryAnalyzer)
}

const (
	version = 1
)

type npmLibraryAnalyzer struct {
	lockParser    godeptypes.Parser
	packageParser *packagejson.Parser
}

func newNpmLibraryAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &npmLibraryAnalyzer{
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
	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		// Find all licenses from package.json files under node_modules dirs
		licenses, err := a.findLicenses(input.FS, filePath)
		if err != nil {
			log.Logger.Errorf("Unable to collect licenses: %s", err)
			licenses = map[string]string{}
		}

		app, err := a.parseNpmPkgLock(input.FS, filePath)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Fill licenses
		for i, lib := range app.Libraries {
			if license, ok := licenses[lib.ID]; ok {
				app.Libraries[i].Licenses = []string{license}
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
	if fileName == types.NpmPkgLock && !xpath.Contains(filePath, "node_modules") {
		return true
	}
	// The file path to package.json - */node_modules/<package_name>/package.json
	// The path is slashed in analyzers.
	dirs := strings.Split(path.Dir(filePath), "/")
	if len(dirs) > 1 && dirs[len(dirs)-2] == "node_modules" && fileName == types.NpmPkg {
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

func (a npmLibraryAnalyzer) parseNpmPkgLock(fsys fs.FS, path string) (*types.Application, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	file, ok := f.(dio.ReadSeekCloserAt)
	if !ok {
		return nil, xerrors.Errorf("type assertion error: %w", err)
	}

	// parse package-lock.json file
	return language.Parse(types.Npm, path, file, a.lockParser)
}

func (a npmLibraryAnalyzer) findLicenses(fsys fs.FS, lockPath string) (map[string]string, error) {
	dir := path.Dir(lockPath)
	root := path.Join(dir, "node_modules")
	if _, err := fs.Stat(fsys, root); errors.Is(err, fs.ErrNotExist) {
		log.Logger.Infof(`To collect the license information of packages in %q, "npm install" needs to be performed beforehand`, lockPath)
		return nil, nil
	}

	// Parse package.json
	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.NpmPkg
	}

	// Traverse node_modules dir and find licenses
	// Note that fs.FS is always slashed regardless of the platform,
	// and path.Join should be used rather than filepath.Join.
	licenses := map[string]string{}
	err := fsutils.WalkDir(fsys, root, required, func(filePath string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		pkg, err := a.packageParser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", filePath, err)
		}

		licenses[pkg.ID] = pkg.License
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}
	return licenses, nil
}
