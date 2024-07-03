package pnpm

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/pnpm"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xpath "github.com/aquasecurity/trivy/pkg/x/path"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePnpm, newPnpmAnalyzer)
}

const version = 2

type pnpmAnalyzer struct {
	logger            *log.Logger
	packageJsonParser *packagejson.Parser
	lockParser        language.Parser
}

func newPnpmAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &pnpmAnalyzer{
		logger:            log.WithPrefix("pnpm"),
		packageJsonParser: packagejson.NewParser(),
		lockParser:        pnpm.NewParser(),
	}, nil
}

func (a pnpmAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.PnpmLock
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		// Find licenses
		licenses, err := a.findLicenses(input.FS, filePath)
		if err != nil {
			a.logger.Error("Unable to collect licenses", log.Err(err))
			licenses = make(map[string][]string)
		}

		// Parse pnpm-lock.yaml
		app, err := language.Parse(types.Pnpm, filePath, r, a.lockParser)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Fill licenses
		for i, lib := range app.Packages {
			if l, ok := licenses[lib.ID]; ok {
				app.Packages[i].Licenses = l
			}
		}

		apps = append(apps, *app)

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("pnpm walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a pnpmAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	// Don't save pnpm-lock.yaml from the `node_modules` directory to avoid duplication and mistakes.
	if fileName == types.PnpmLock && !xpath.Contains(filePath, "node_modules") {
		return true
	}

	// Save package.json files only from the `node_modules` directory.
	// Required to search for licenses.
	if fileName == types.NpmPkg && xpath.Contains(filePath, "node_modules") {
		return true
	}

	return false
}

func (a pnpmAnalyzer) Type() analyzer.Type {
	return analyzer.TypePnpm
}

func (a pnpmAnalyzer) Version() int {
	return version
}

func (a pnpmAnalyzer) findLicenses(fsys fs.FS, lockPath string) (map[string][]string, error) {
	dir := path.Dir(lockPath)
	root := path.Join(dir, "node_modules")
	if _, err := fs.Stat(fsys, root); errors.Is(err, fs.ErrNotExist) {
		a.logger.Info(`To collect the license information of packages, "pnpm install" needs to be performed beforehand`,
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
		pkg, err := a.packageJsonParser.Parse(r)
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
