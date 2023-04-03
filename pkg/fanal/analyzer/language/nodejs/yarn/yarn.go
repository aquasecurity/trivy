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
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/yarn"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
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
	packageJsonParser *packagejson.Parser
	lockParser        godeptypes.Parser
	comparer          npm.Comparer
}

func newYarnAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &yarnAnalyzer{
		packageJsonParser: packagejson.NewParser(),
		lockParser:        yarn.NewParser(),
		comparer:          npm.Comparer{},
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
			log.Logger.Warnf("Unable to parse %q to remove dev dependencies: %s", filepath.Join(filepath.Dir(path), types.NpmPkg), err)
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
	return language.Parse(types.Yarn, path, r, a.lockParser)
}

func (a yarnAnalyzer) removeDevDependencies(fsys fs.FS, dir string, app *types.Application) error {
	packageJsonPath := filepath.Join(dir, types.NpmPkg)
	directDeps, err := a.parsePackageJsonDependencies(fsys, packageJsonPath)
	if errors.Is(err, fs.ErrNotExist) {
		log.Logger.Debugf("Yarn: %s not found", packageJsonPath)
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", dir, err)
	}

	// yarn.lock file can contain same libraries with different versions
	// save versions separately for version comparison by comparator
	pkgIDs := lo.SliceToMap(app.Libraries, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	// Identify direct dependencies
	pkgs := map[string]types.Package{}
	for name, constraint := range directDeps {
		for _, pkg := range app.Libraries {
			if pkg.Name != name {
				continue
			}

			// npm has own comparer to compare versions
			if match, err := a.comparer.MatchVersion(pkg.Version, constraint); err != nil {
				return xerrors.Errorf("unable to match version for %s", pkg.Name)
			} else if match {
				// Mark as a direct dependency
				pkg.Indirect = false
				pkgs[pkg.ID] = pkg
				break
			}
		}
	}

	// Walk indirect dependencies
	// Since it starts from direct dependencies, devDependencies will not appear in this walk.
	for _, pkg := range pkgs {
		a.walkIndirectDependencies(pkg, pkgIDs, pkgs)
	}

	pkgSlice := maps.Values(pkgs)
	sort.Sort(types.Packages(pkgSlice))

	// Save only prod libraries
	app.Libraries = pkgSlice
	return nil
}

func (a yarnAnalyzer) walkIndirectDependencies(pkg types.Package, pkgIDs map[string]types.Package, deps map[string]types.Package) {
	for _, pkgID := range pkg.DependsOn {
		if _, ok := deps[pkgID]; ok {
			continue
		}

		dep, ok := pkgIDs[pkgID]
		if !ok {
			continue
		}

		dep.Indirect = true
		deps[dep.ID] = dep
		a.walkIndirectDependencies(dep, pkgIDs, deps)
	}
}

func (a yarnAnalyzer) parsePackageJsonDependencies(fsys fs.FS, path string) (map[string]string, error) {
	// Parse package.json
	f, err := fsys.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	pkg, err := a.packageJsonParser.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("parse error: %w", err)
	}

	// Merge dependencies and optionalDependencies
	return lo.Assign(pkg.Dependencies, pkg.OptionalDependencies), nil
}
