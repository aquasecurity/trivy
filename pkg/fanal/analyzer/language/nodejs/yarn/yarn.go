package yarn

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/yarn"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/license"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeYarn, newYarnAnalyzer)
}

const version = 2

type yarnAnalyzer struct {
	packageJsonParser *packagejson.Parser
	lockParser        godeptypes.Parser
	comparer          npm.Comparer
	license           *license.License
}

func newYarnAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &yarnAnalyzer{
		packageJsonParser: packagejson.NewParser(),
		lockParser:        yarn.NewParser(),
		comparer:          npm.Comparer{},
		license:           license.NewLicense(opt.LicenseScannerOption.ClassifierConfidenceLevel),
	}, nil
}

func (a yarnAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.YarnLock
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		// Parse yarn.lock
		app, err := a.parseYarnLock(filePath, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		licenses, err := a.traverseLicenses(input.FS, filePath)
		if err != nil {
			log.Logger.Debugf("Unable to traverse licenses: %s", err)
		}

		// Parse package.json alongside yarn.lock to find direct deps and mark dev deps
		if err = a.analyzeDependencies(input.FS, path.Dir(filePath), app); err != nil {
			log.Logger.Warnf("Unable to parse %q to remove dev dependencies: %s", path.Join(path.Dir(filePath), types.NpmPkg), err)
		}

		// Fill licenses
		for i, lib := range app.Libraries {
			if l, ok := licenses[lib.ID]; ok {
				app.Libraries[i].Licenses = l
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

	if fileName == types.YarnLock &&
		// skipping yarn.lock in cache folders
		lo.Some(dirs, []string{
			"node_modules",
			".yarn",
		}) {
		return false
	}

	if fileName == types.YarnLock ||
		fileName == types.NpmPkg ||
		strings.HasPrefix(strings.ToLower(fileName), "license") {
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

func splitPath(filePath string) (dirs []string, fileName string) {
	fileName = filepath.Base(filePath)
	// The path is slashed in analyzers.
	dirs = strings.Split(path.Dir(filePath), "/")
	return dirs, fileName
}

func (a yarnAnalyzer) Type() analyzer.Type {
	return analyzer.TypeYarn
}

func (a yarnAnalyzer) Version() int {
	return version
}

func (a yarnAnalyzer) parseYarnLock(path string, r io.Reader) (*types.Application, error) {
	return language.Parse(types.Yarn, path, r, a.lockParser)
}

// analyzeDependencies analyzes the package.json file next to yarn.lock,
// distinguishing between direct and transitive dependencies as well as production and development dependencies.
func (a yarnAnalyzer) analyzeDependencies(fsys fs.FS, dir string, app *types.Application) error {
	packageJsonPath := path.Join(dir, types.NpmPkg)
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

	walkDirFunc := func(path string, d fs.DirEntry, r io.Reader) error {
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

func (a yarnAnalyzer) traverseLicenses(fsys fs.FS, lockPath string) (map[string][]string, error) {
	sub, err := fs.Sub(fsys, path.Dir(lockPath))
	if err != nil {
		return nil, xerrors.Errorf("fs error: %w", err)
	}
	var errs error

	// Yarn v1
	licenses, err := a.traverseYarnClassicPkgs(sub)
	if err == nil {
		return licenses, nil
	}
	errs = multierror.Append(errs, err)

	// Yarn v2+
	licenses, err = a.traverseYarnModernPkgs(sub)
	if err == nil {
		return licenses, nil
	}
	errs = multierror.Append(errs, err)

	return nil, errs
}

func (a yarnAnalyzer) traverseYarnClassicPkgs(fsys fs.FS) (map[string][]string, error) {
	return a.license.Traverse(fsys, "node_modules")
}

func (a yarnAnalyzer) traverseYarnModernPkgs(fsys fs.FS) (map[string][]string, error) {
	sub, err := fs.Sub(fsys, ".yarn")
	if err != nil {
		return nil, xerrors.Errorf("fs error: %w", err)
	}

	var errs error
	licenses := map[string][]string{}

	if ll, err := a.traverseUnpluggedDir(sub); err != nil {
		errs = multierror.Append(errs, err)
	} else {
		licenses = lo.Assign(licenses, ll)
	}

	if ll, err := a.traverseCacheDir(sub); err != nil {
		errs = multierror.Append(errs, err)
	} else {
		licenses = lo.Assign(licenses, ll)
	}

	if len(licenses) == 0 {
		return nil, errs
	}

	return licenses, nil
}

func (a yarnAnalyzer) traverseUnpluggedDir(fsys fs.FS) (map[string][]string, error) {
	// `unplugged` hold machine-specific build artifacts
	// Traverse .yarn/unplugged dir
	return a.license.Traverse(fsys, "unplugged")
}

func (a yarnAnalyzer) traverseCacheDir(fsys fs.FS) (map[string][]string, error) {
	// Traverse .yarn/cache dir
	licenses := map[string][]string{}
	err := fsutils.WalkDir(fsys, "cache", fsutils.RequiredExt(".zip"),
		func(filePath string, d fs.DirEntry, r io.Reader) error {
			fi, err := d.Info()
			if err != nil {
				return xerrors.Errorf("file stat error: %w", err)
			}

			rr, err := xio.NewReadSeekerAt(r)
			if err != nil {
				return xerrors.Errorf("reader error: %w", err)
			}

			zr, err := zip.NewReader(rr, fi.Size())
			if err != nil {
				return xerrors.Errorf("zip reader error: %w", err)
			}

			if l, err := a.license.Traverse(zr, "node_modules"); err != nil {
				return xerrors.Errorf("license traverse error: %w", err)
			} else {
				licenses = lo.Assign(licenses, l)
			}
			return nil
		})

	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}

	return licenses, nil
}
