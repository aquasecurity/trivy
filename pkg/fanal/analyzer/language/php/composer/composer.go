package composer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/php/composer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeComposer, newComposerAnalyzer)
}

const composerAnalyzerVersion = 1

var requiredFiles = []string{
	types.ComposerLock,
	types.ComposerJson,
}

type composerAnalyzer struct {
	lockParser language.Parser
}

func newComposerAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &composerAnalyzer{
		lockParser: composer.NewParser(),
	}, nil
}

func (a composerAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.ComposerLock
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
		// Parse composer.lock
		app, err := a.parseComposerLock(path, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse composer.json alongside composer.lock to identify the direct dependencies
		if err = a.mergeComposerJson(input.FS, filepath.Dir(path), app); err != nil {
			log.Warn("Unable to parse composer.json to identify direct dependencies",
				log.FilePath(filepath.Join(filepath.Dir(path), types.ComposerJson)), log.Err(err))
		}
		sort.Sort(app.Packages)
		apps = append(apps, *app)

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("composer walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a composerAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	if !slices.Contains(requiredFiles, fileName) {
		return false
	}

	// Skip `composer.lock` inside `vendor` folder
	if slices.Contains(strings.Split(filePath, "/"), "vendor") {
		return false
	}
	return true
}

func (a composerAnalyzer) Type() analyzer.Type {
	return analyzer.TypeComposer
}

func (a composerAnalyzer) Version() int {
	return composerAnalyzerVersion
}

func (a composerAnalyzer) parseComposerLock(path string, r io.Reader) (*types.Application, error) {
	return language.Parse(types.Composer, path, r, a.lockParser)
}

func (a composerAnalyzer) mergeComposerJson(fsys fs.FS, dir string, app *types.Application) error {
	// Parse composer.json to identify the direct dependencies
	path := filepath.Join(dir, types.ComposerJson)
	p, err := a.parseComposerJson(fsys, path)
	if errors.Is(err, fs.ErrNotExist) {
		// Assume all the packages are direct dependencies as it cannot identify them from composer.lock
		log.Debug("Unable to determine the direct dependencies, composer.json not found", log.FilePath(path))
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", path, err)
	}

	for i, pkg := range app.Packages {
		// Identify the direct/transitive dependencies
		if _, ok := p[pkg.Name]; ok {
			app.Packages[i].Relationship = types.RelationshipDirect
		} else {
			app.Packages[i].Indirect = true
			app.Packages[i].Relationship = types.RelationshipIndirect
		}
	}

	return nil
}

type composerJson struct {
	Require map[string]string `json:"require"`
}

func (a composerAnalyzer) parseComposerJson(fsys fs.FS, path string) (map[string]string, error) {
	// Parse composer.json
	f, err := fsys.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	jsonFile := composerJson{}
	err = json.NewDecoder(f).Decode(&jsonFile)
	if err != nil {
		return nil, xerrors.Errorf("json decode error: %w", err)
	}
	return jsonFile.Require, nil
}
