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
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/yarn"
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

// Taken from Yarn
// cf. https://github.com/yarnpkg/yarn/blob/328fd596de935acc6c3e134741748fcc62ec3739/src/resolvers/exotics/registry-resolver.js#L12
var fragmentRegexp = regexp.MustCompile(`(\S+):(@?.*?)(@(.*?)|)$`)

type yarnAnalyzer struct {
	logger            *log.Logger
	packageJsonParser *packagejson.Parser
	comparer          npm.Comparer
	license           *license.License
}

func newYarnAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &yarnAnalyzer{
		logger:            log.WithPrefix("yarn"),
		packageJsonParser: packagejson.NewParser(),
		comparer:          npm.Comparer{},
		license:           license.NewLicense(opt.LicenseScannerOption.ClassifierConfidenceLevel),
	}, nil
}

type parserWithPatterns struct {
	patterns map[string][]string
}

func (p *parserWithPatterns) Parse(r xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error) {
	pkgs, deps, patterns, err := yarn.NewParser().Parse(r)
	p.patterns = patterns
	return pkgs, deps, err
}

func (a yarnAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.YarnLock
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		parser := &parserWithPatterns{}
		// Parse yarn.lock
		app, err := language.Parse(types.Yarn, filePath, r, parser)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		licenses, err := a.traverseLicenses(input.FS, filePath)
		if err != nil {
			a.logger.Debug("Unable to traverse licenses", log.Err(err))
		}

		// Parse package.json alongside yarn.lock to find direct deps and mark dev deps
		if err = a.analyzeDependencies(input.FS, path.Dir(filePath), app, parser.patterns); err != nil {
			a.logger.Warn("Unable to parse package.json to remove dev dependencies",
				log.FilePath(path.Join(path.Dir(filePath), types.NpmPkg)), log.Err(err))
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

// analyzeDependencies analyzes the package.json file next to yarn.lock,
// distinguishing between direct and transitive dependencies as well as production and development dependencies.
func (a yarnAnalyzer) analyzeDependencies(fsys fs.FS, dir string, app *types.Application, patterns map[string][]string) error {
	packageJsonPath := path.Join(dir, types.NpmPkg)
	directDeps, directDevDeps, err := a.parsePackageJsonDependencies(fsys, packageJsonPath)
	if errors.Is(err, fs.ErrNotExist) {
		a.logger.Debug("package.json not found", log.FilePath(packageJsonPath))
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", dir, err)
	}

	// yarn.lock file can contain same packages with different versions
	// save versions separately for version comparison by comparator
	pkgIDs := lo.SliceToMap(app.Packages, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	// Walk prod dependencies
	pkgs, err := a.walkDependencies(app.Packages, pkgIDs, directDeps, patterns, false)
	if err != nil {
		return xerrors.Errorf("unable to walk dependencies: %w", err)
	}

	// Walk dev dependencies
	devPkgs, err := a.walkDependencies(app.Packages, pkgIDs, directDevDeps, patterns, true)
	if err != nil {
		return xerrors.Errorf("unable to walk dependencies: %w", err)
	}

	// Merge prod and dev dependencies.
	// If the same package is found in both prod and dev dependencies, use the one in prod.
	pkgs = lo.Assign(devPkgs, pkgs)

	pkgSlice := lo.Values(pkgs)
	sort.Sort(types.Packages(pkgSlice))

	// Save packages
	app.Packages = pkgSlice
	return nil
}

func (a yarnAnalyzer) walkDependencies(pkgs []types.Package, pkgIDs map[string]types.Package,
	directDeps map[string]string, patterns map[string][]string, dev bool) (map[string]types.Package, error) {

	// Identify direct dependencies
	directPkgs := make(map[string]types.Package)
	for _, pkg := range pkgs {
		constraint, ok := directDeps[pkg.Name]
		if !ok {
			continue
		}

		// Handle aliases
		// cf. https://classic.yarnpkg.com/lang/en/docs/cli/add/#toc-yarn-add-alias
		if m := fragmentRegexp.FindStringSubmatch(constraint); len(m) == 5 {
			pkg.Name = m[2] // original name
			constraint = m[4]
		}

		// Try to find an exact match to the pattern.
		// In some cases, patterns from yarn.lock and package.json may not match (e.g., yarn v2 uses the allowed version for ID).
		// Therefore, if the patterns don't match - compare versions.
		if pkgPatterns, found := patterns[pkg.ID]; !found || !slices.Contains(pkgPatterns, dependency.ID(types.Yarn, pkg.Name, constraint)) {
			// npm has own comparer to compare versions
			if match, err := a.comparer.MatchVersion(pkg.Version, constraint); err != nil {
				return nil, xerrors.Errorf("unable to match version for %s", pkg.Name)
			} else if !match {
				continue
			}
		}

		// Mark as a direct dependency
		pkg.Indirect = false
		pkg.Relationship = types.RelationshipDirect
		pkg.Dev = dev
		directPkgs[pkg.ID] = pkg

	}

	// Walk indirect dependencies
	for _, pkg := range directPkgs {
		a.walkIndirectDependencies(pkg, pkgIDs, directPkgs)
	}

	return directPkgs, nil
}

func (a yarnAnalyzer) walkIndirectDependencies(pkg types.Package, pkgIDs, deps map[string]types.Package) {
	for _, pkgID := range pkg.DependsOn {
		if _, ok := deps[pkgID]; ok {
			continue
		}

		dep, ok := pkgIDs[pkgID]
		if !ok {
			continue
		}

		dep.Indirect = true
		dep.Relationship = types.RelationshipIndirect
		dep.Dev = pkg.Dev
		deps[dep.ID] = dep
		a.walkIndirectDependencies(dep, pkgIDs, deps)
	}
}

func (a yarnAnalyzer) parsePackageJsonDependencies(fsys fs.FS, filePath string) (map[string]string, map[string]string, error) {
	// Parse package.json
	f, err := fsys.Open(filePath)
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
		pkgs, err := a.traverseWorkspaces(fsys, path.Dir(filePath), rootPkg.Workspaces)
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

func (a yarnAnalyzer) traverseWorkspaces(fsys fs.FS, dir string, workspaces []string) ([]packagejson.Package, error) {
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
		// We need to add the path to the `package.json` file
		// to properly get the pattern to search in `fs`
		workspace = path.Join(dir, workspace)
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
	licenses := make(map[string][]string)

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
	licenses := make(map[string][]string)
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
