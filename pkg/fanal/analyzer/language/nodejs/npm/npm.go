package npm

import (
	"context"
	"errors"
	"io/fs"
	"os"
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
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeNpmPkgLock, newNpmLibraryAnalyzer)
}

const (
	version = 1
)

type npmLibraryAnalyzer struct {
	lockParser    godeptypes.Parser
	packageParser godeptypes.Parser
}

func newNpmLibraryAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &npmLibraryAnalyzer{
		lockParser:    npm.NewParser(),
		packageParser: packagejson.NewParser(),
	}, nil
}

func (a npmLibraryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application
	licenses := map[string][]string{}

	err := fs.WalkDir(input.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if !d.Type().IsRegular() {
			return nil
		}

		// Parse package-json.lock files
		if filepath.Base(path) == types.NpmPkgLock {
			app, err := a.parseNpmPkgLock(input.FS, path)
			if err != nil {
				return xerrors.Errorf("parse error: %w", err)
			} else if app == nil {
				return nil
			}
			apps = append(apps, *app)
			return nil
		}

		// Find all licenses from package.json files from node_modules dirs
		licenses, err = a.findLicenses(input.FS, path, licenses)
		if err != nil {
			return xerrors.Errorf("license find error: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("package-lock.json/package.json walk error: %w", err)
	}

	// fill licenses
	for i, app := range apps {
		for j, lib := range app.Libraries {
			if license, ok := licenses[lib.ID]; ok {
				apps[i].Libraries[j].Licenses = license
			}
		}
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a npmLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	if fileName == types.NpmPkgLock {
		return true
	}
	// path to package.json files - */node_modules/<package_name>/package.json
	dirs := strings.Split(filepath.Dir(filePath), "/")
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
	libs, deps, err := a.lockParser.Parse(file)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse package-lock.json: %w", err)
	}
	return language.ToApplication(types.Npm, path, "", libs, deps), nil
}

func (a npmLibraryAnalyzer) findLicenses(fsys fs.FS, path string, foundLicenses map[string][]string) (map[string][]string, error) {
	lib, err := a.parseNpmPkg(fsys, path)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse %q: %w", path, err)
	}
	if _, ok := foundLicenses[lib.ID]; !ok {
		foundLicenses[lib.ID] = []string{lib.License}
	}
	return foundLicenses, nil
}

func (a npmLibraryAnalyzer) parseNpmPkg(fsys fs.FS, path string) (godeptypes.Library, error) {
	f, err := fsys.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		log.Logger.Debugf("%q not found", path)
		return godeptypes.Library{}, nil
	} else if err != nil {
		return godeptypes.Library{}, xerrors.Errorf("file open error: %w", err)
	}

	file, ok := f.(dio.ReadSeekCloserAt)
	if !ok {
		return godeptypes.Library{}, xerrors.Errorf("type assertion error: %w", err)
	}
	defer func() { _ = f.Close() }()

	lib, _, err := a.packageParser.Parse(file)
	// package.json always contains only 1 library.
	// https://github.com/aquasecurity/go-dep-parser/blob/63a15cdc6bc3aaeb58c4172b275deadde4d55928/pkg/nodejs/packagejson/parse.go#L33-L37
	if err != nil || len(lib) != 1 {
		return godeptypes.Library{}, xerrors.Errorf("unable to parse %q: %w", path, err)
	}
	return lib[0], err
}
