package yarn

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/samber/lo"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/yarn"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	godeputils "github.com/aquasecurity/go-dep-parser/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(types.Yarn, newYarnAnalyzer)
}

const version = 1

type yarnAnalyzer struct {
	packageJsonParser PackageJsonParser
	lockParser        godeptypes.Parser
}

func newYarnAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &yarnAnalyzer{
		packageJsonParser: NewPackageJsonParser(),
		lockParser:        yarn.NewParser(),
	}, nil
}

func (a yarnAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.YarnLock
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		// Parse yarn.lock
		app, err := a.parseYarnLock(path, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse package.json alongside yarn.lock to remove dev dependencies
		if err = a.removeDevDependencies(input.FS, filepath.Dir(path), app); err != nil {
			return err
		}
		apps = append(apps, *app)

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("yarn walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a yarnAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return fileName == types.YarnLock || fileName == types.NpmPkg
}

func (a yarnAnalyzer) Type() analyzer.Type {
	return analyzer.TypeYarn
}

func (a yarnAnalyzer) Version() int {
	return version
}

func (a yarnAnalyzer) parseYarnLock(path string, r dio.ReadSeekerAt) (*types.Application, error) {
	libs, deps, err := a.lockParser.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse poetry.lock: %w", err)
	}
	return language.ToApplication(types.Yarn, path, "", libs, deps), nil
}

func (a yarnAnalyzer) removeDevDependencies(fsys fs.FS, path string, app *types.Application) error {
	libs := map[string]types.Package{}
	packageJsonPath := filepath.Join(path, types.NpmPkg)
	packageJson, err := a.parsePackageJson(fsys, packageJsonPath)
	if errors.Is(err, fs.ErrNotExist) {
		log.Logger.Debugf("Yarn: %s not found", path)
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", path, err)
	}
	queue := newQueue()
	usedLibs := lo.SliceToMap(app.Libraries, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	// add direct deps to the queue
	for n, v := range packageJson.Dependencies {
		item := Item{
			id:       godeputils.PackageID(n, v),
			indirect: false,
		}
		queue.enqueue(item)
	}

	for !queue.isEmpty() {
		dep := queue.dequeue()

		lib, ok := usedLibs[dep.id]
		if !ok {
			return xerrors.Errorf("unable to find dependency: %s", dep)
		}

		// overwrite Indirect value
		lib.Indirect = dep.indirect

		// skip if we have already added this library
		if _, ok := libs[lib.ID]; ok {
			continue
		}
		libs[lib.ID] = lib

		// add indirect deps to the queue
		for _, d := range lib.DependsOn {
			item := Item{
				id:       d,
				indirect: true,
			}
			queue.enqueue(item)
		}
	}

	libSlice := maps.Values(libs)
	sort.Slice(libSlice, func(i, j int) bool {
		return libSlice[i].ID < libSlice[j].ID
	})

	// Save only prod libraries
	app.Libraries = libSlice
	return nil
}

func (a yarnAnalyzer) parsePackageJson(fsys fs.FS, path string) (PackageJson, error) {
	// Parse package.json
	f, err := fsys.Open(path)
	if err != nil {
		return PackageJson{}, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	packageJson, err := a.packageJsonParser.Parse(f)
	if err != nil {
		return PackageJson{}, err
	}
	return packageJson, nil
}
