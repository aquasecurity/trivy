package yarn

import (
	"archive/zip"
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

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

		licenses := map[string]string{}

		traverseFunc := func(pkg packagejson.Package) error {
			// Find all licenses from package.json files under node_modules or .yarn dirs
			if pkg.License != "" {
				licenses[pkg.ID] = pkg.License
			}
			return nil
		}

		if err := a.traversePkgs(input.FS, path, traverseFunc); err != nil {
			log.Logger.Errorf("Unable to traverse packages: %s", err)
		}

		// Parse package.json alongside yarn.lock to find direct deps and mark dev deps
		if err = a.analyzeDependencies(input.FS, filepath.Dir(path), app); err != nil {
			log.Logger.Warnf("Unable to parse %q to remove dev dependencies: %s", filepath.Join(filepath.Dir(path), types.NpmPkg), err)
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
		return nil, xerrors.Errorf("yarn walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a yarnAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dirs, fileName := splitPath(filePath)
	if fileName == types.YarnLock || fileName == types.NpmPkg {
		return true
	}
	// The path is slashed in analyzers.
	l := len(dirs)
	// Valid path to the zip file - **/.yarn/cache/*.zip
	if l > 1 && dirs[l-2] == ".yarn" && dirs[l-1] == "cache" && path.Ext(fileName) == ".zip" {
		return true
	}

	return false
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

// analyzeDependencies analyzes the package.json file next to yarn.lock,
// distinguishing between direct and transitive dependencies as well as production and development dependencies.
func (a yarnAnalyzer) analyzeDependencies(fsys fs.FS, dir string, app *types.Application) error {
	packageJsonPath := filepath.Join(dir, types.NpmPkg)
	directDeps, directDevDeps, err := a.parsePackageJsonDependencies(fsys, packageJsonPath)
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

	// Walk prod dependencies
	pkgs, err := a.walkDependencies(app.Libraries, pkgIDs, directDeps, false)
	if err != nil {
		return xerrors.Errorf("unable to walk dependencies: %w", err)
	}

	// Walk dev dependencies
	devPkgs, err := a.walkDependencies(app.Libraries, pkgIDs, directDevDeps, true)
	if err != nil {
		return xerrors.Errorf("unable to walk dependencies: %w", err)
	}

	// Merge prod and dev dependencies.
	// If the same package is found in both prod and dev dependencies, use the one in prod.
	pkgs = lo.Assign(devPkgs, pkgs)

	pkgSlice := maps.Values(pkgs)
	sort.Sort(types.Packages(pkgSlice))

	// Save libraries
	app.Libraries = pkgSlice
	return nil
}

func (a yarnAnalyzer) walkDependencies(libs []types.Package, pkgIDs map[string]types.Package,
	directDeps map[string]string, dev bool) (map[string]types.Package, error) {

	// Identify direct dependencies
	pkgs := map[string]types.Package{}
	for _, pkg := range libs {
		if constraint, ok := directDeps[pkg.Name]; ok {
			// npm has own comparer to compare versions
			if match, err := a.comparer.MatchVersion(pkg.Version, constraint); err != nil {
				return nil, xerrors.Errorf("unable to match version for %s", pkg.Name)
			} else if match {
				// Mark as a direct dependency
				pkg.Indirect = false
				pkg.Dev = dev
				pkgs[pkg.ID] = pkg
			}
		}
	}

	// Walk indirect dependencies
	for _, pkg := range pkgs {
		a.walkIndirectDependencies(pkg, pkgIDs, pkgs)
	}

	return pkgs, nil
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
		dep.Dev = pkg.Dev
		deps[dep.ID] = dep
		a.walkIndirectDependencies(dep, pkgIDs, deps)
	}
}

func (a yarnAnalyzer) parsePackageJsonDependencies(fsys fs.FS, path string) (map[string]string, map[string]string, error) {
	// Parse package.json
	f, err := fsys.Open(path)
	if err != nil {
		return nil, nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	rootPkg, err := a.packageJsonParser.Parse(f)
	if err != nil {
		return nil, nil, xerrors.Errorf("parse error: %w", err)
	}

	// Merge dependencies and optionalDependencies
	dependencies := lo.Assign(rootPkg.Dependencies, rootPkg.OptionalDependencies)
	devDependencies := rootPkg.DevDependencies

	if len(rootPkg.Workspaces) > 0 {
		pkgs, err := a.traverseWorkspaces(fsys, rootPkg.Workspaces)
		if err != nil {
			return nil, nil, xerrors.Errorf("traverse workspaces error: %w", err)
		}
		for _, pkg := range pkgs {
			dependencies = lo.Assign(dependencies, pkg.Dependencies, pkg.OptionalDependencies)
			devDependencies = lo.Assign(devDependencies, pkg.DevDependencies)
		}
	}

	return dependencies, devDependencies, nil
}

func (a yarnAnalyzer) traverseWorkspaces(fsys fs.FS, workspaces []string) ([]packagejson.Package, error) {
	var pkgs []packagejson.Package

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.NpmPkg
	}

	walkDirFunc := func(path string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		pkg, err := a.packageJsonParser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", path, err)
		}
		pkgs = append(pkgs, pkg)
		return nil
	}

	for _, workspace := range workspaces {
		matches, err := fs.Glob(fsys, workspace)
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			if err := fsutils.WalkDir(fsys, match, required, walkDirFunc); err != nil {
				return nil, xerrors.Errorf("walk error: %w", err)
			}
		}

	}
	return pkgs, nil
}

type traverseFunc func(pkg packagejson.Package) error

func (a yarnAnalyzer) traversePkgs(fsys fs.FS, lockPath string, fn traverseFunc) error {
	dir := filepath.Dir(lockPath)

	nodeModulesPath := path.Join(dir, "node_modules")

	if _, err := fs.Stat(fsys, nodeModulesPath); errors.Is(err, fs.ErrNotExist) {
		// try to find for yarn v2+
		return a.traverseYarnModernPkgs(fsys, dir, fn)
	} else if err != nil {
		return xerrors.Errorf("unable to parse %q: %w", nodeModulesPath, err)
	}

	return a.traverseYarnClassicPkgs(fsys, nodeModulesPath, fn)
}

func isNodeModulesPkg(path string, _ fs.DirEntry) bool {
	return strings.HasSuffix(path, "package.json")
}

func splitPath(filePath string) (dirs []string, fileName string) {
	fileName = filepath.Base(filePath)
	// The path is slashed in analyzers.
	dirs = strings.Split(path.Dir(filePath), "/")
	return dirs, fileName
}

func (a yarnAnalyzer) traverseYarnClassicPkgs(fsys fs.FS, path string, fn traverseFunc) error {
	// Traverse node_modules dir
	// Note that fs.FS is always slashed regardless of the platform,
	// and path.Join should be used rather than filepath.Join.
	walkDirFunc := func(filePath string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		pkg, err := a.packageJsonParser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", filePath, err)
		}
		return fn(pkg)
	}
	if err := fsutils.WalkDir(fsys, path, isNodeModulesPkg, walkDirFunc); err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}
	return nil
}

func (a yarnAnalyzer) traverseYarnModernPkgs(fsys fs.FS, root string, fn traverseFunc) error {
	yarnDir := path.Join(root, ".yarn")
	if _, err := fs.Stat(fsys, yarnDir); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %q: %w", yarnDir, err)
	}

	if err := a.traverseUnpluggedFolder(fsys, yarnDir, fn); err != nil {
		return err
	}
	if err := a.traverseCacheFolder(fsys, yarnDir, fn); err != nil {
		return err
	}

	return nil
}

func (a yarnAnalyzer) traverseUnpluggedFolder(fsys fs.FS, root string, fn traverseFunc) error {
	// `unplugged` hold machine-specific build artifacts
	unpluggedPath := path.Join(root, "unplugged")
	if _, err := fs.Stat(fsys, unpluggedPath); err != nil {
		return nil
	}

	// Traverse .yarn/unplugged dir
	err := fsutils.WalkDir(fsys, unpluggedPath, isNodeModulesPkg, func(path string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		pkg, err := a.packageJsonParser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", path, err)
		}
		return fn(pkg)
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	return nil
}

func (a yarnAnalyzer) traverseCacheFolder(fsys fs.FS, root string, fn traverseFunc) error {
	cachePath := path.Join(root, "cache")
	if _, err := fs.Stat(fsys, cachePath); err != nil {
		return nil
	}

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Ext(path) == ".zip"
	}

	// Traverse .yarn/cache dir
	err := fsutils.WalkDir(fsys, cachePath, required, func(path string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		fi, err := d.Info()
		if err != nil {
			return xerrors.Errorf("file stat error: %w", err)
		}

		zr, err := zip.NewReader(r, fi.Size())
		if err != nil {
			return xerrors.Errorf("zip reader error: %w", err)
		}

		for _, f := range zr.File {
			if filepath.Base(f.Name) != types.NpmPkg {
				continue
			}
			pkg, err := a.parsePackageJsonFromZip(f)
			if err != nil {
				return xerrors.Errorf("unable to parse %q: %w", path, err)
			}
			return fn(pkg)
		}

		return nil
	})

	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	return nil
}

func (a yarnAnalyzer) parsePackageJsonFromZip(f *zip.File) (packagejson.Package, error) {
	pkgFile, err := f.Open()
	if err != nil {
		return packagejson.Package{}, xerrors.Errorf("file open error: %w", err)
	}
	defer pkgFile.Close()
	pkg, err := a.packageJsonParser.Parse(pkgFile)
	if err != nil {
		return packagejson.Package{}, err
	}

	return pkg, nil
}
