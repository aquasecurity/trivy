package yarn

import (
	"archive/zip"
	"cmp"
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
	"github.com/aquasecurity/trivy/pkg/set"
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

func (p *parserWithPatterns) Parse(ctx context.Context, r xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error) {
	pkgs, deps, patterns, err := yarn.NewParser().Parse(ctx, r)
	p.patterns = patterns
	return pkgs, deps, err
}

func (a yarnAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.YarnLock || input.FilePatterns.Match(path)
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		parser := &parserWithPatterns{}
		// Parse yarn.lock
		app, err := language.Parse(ctx, types.Yarn, filePath, r, parser)
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
	root, workspaces, err := a.parsePackageJSON(fsys, packageJsonPath)
	if errors.Is(err, fs.ErrNotExist) {
		a.logger.Debug("package.json not found", log.FilePath(packageJsonPath))
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse root package.json: %w", err)
	}

	// Since yarn.lock file can contain same packages with different versions
	// we need to save versions separately for version comparison.
	pkgs := lo.SliceToMap(app.Packages, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	if err := a.resolveRootDependencies(&root, pkgs, patterns); err != nil {
		return xerrors.Errorf("unable to resolve root dependencies: %w", err)
	}

	if err := a.resolveWorkspaceDependencies(workspaces, pkgs, patterns); err != nil {
		return xerrors.Errorf("unable to resolve workspace dependencies: %w", err)
	}

	pkgSlice := lo.Values(pkgs)
	sort.Sort(types.Packages(pkgSlice))

	// Save packages
	app.Packages = pkgSlice
	return nil
}

func (a yarnAnalyzer) parsePackageJSON(fsys fs.FS, filePath string) (packagejson.Package, []packagejson.Package, error) {
	// Parse package.json
	f, err := fsys.Open(filePath)
	if err != nil {
		return packagejson.Package{}, nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	root, err := a.packageJsonParser.Parse(f)
	if err != nil {
		return packagejson.Package{}, nil, xerrors.Errorf("parse error: %w", err)
	}

	root.Package.ID = cmp.Or(root.Package.ID, filePath) // In case the package.json doesn't have a name or version
	root.Package.Relationship = types.RelationshipRoot

	workspaces, err := a.traverseWorkspaces(fsys, path.Dir(filePath), root.Workspaces)
	if err != nil {
		return packagejson.Package{}, nil, xerrors.Errorf("traverse workspaces error: %w", err)
	}
	for i := range workspaces {
		workspaces[i].Package.Relationship = types.RelationshipWorkspace

		// Add workspace as a child of root
		root.DependsOn = append(root.DependsOn, workspaces[i].ID)
	}

	return root, workspaces, nil
}

func (a yarnAnalyzer) resolveRootDependencies(root *packagejson.Package, pkgs map[string]types.Package,
	patterns map[string][]string) error {
	if err := a.resolveDependencies(root, pkgs, patterns); err != nil {
		return xerrors.Errorf("unable to resolve dependencies: %w", err)
	}

	// Add root package to the package map
	slices.Sort(root.Package.DependsOn)
	pkgs[root.Package.ID] = root.Package

	return nil
}

func (a yarnAnalyzer) resolveWorkspaceDependencies(workspaces []packagejson.Package, pkgs map[string]types.Package,
	patterns map[string][]string) error {
	if len(workspaces) == 0 {
		return nil
	}

	for _, workspace := range workspaces {
		if err := a.resolveDependencies(&workspace, pkgs, patterns); err != nil {
			return xerrors.Errorf("unable to resolve dependencies: %w", err)
		}

		// Add workspace to the package map
		slices.Sort(workspace.Package.DependsOn)
		pkgs[workspace.ID] = workspace.Package
	}

	return nil
}

// resolveDependencies resolves production and development dependencies from direct dependencies and patterns.
// It also flags dependencies as direct or indirect and updates the dependencies of the parent package.
func (a yarnAnalyzer) resolveDependencies(pkg *packagejson.Package, pkgs map[string]types.Package, patterns map[string][]string) error {
	// Recursively walk dependencies and flags development dependencies.
	// Walk development dependencies first to avoid overwriting production dependencies.
	directDevDeps := pkg.DevDependencies
	if err := a.walkDependencies(&pkg.Package, pkgs, directDevDeps, patterns, true); err != nil {
		return xerrors.Errorf("unable to walk dependencies: %w", err)
	}

	// Recursively walk dependencies and flags production dependencies.
	directProdDeps := lo.Assign(pkg.Dependencies, pkg.OptionalDependencies)
	if err := a.walkDependencies(&pkg.Package, pkgs, directProdDeps, patterns, false); err != nil {
		return xerrors.Errorf("unable to walk dependencies: %w", err)
	}

	return nil
}

// walkDependencies recursively walk dependencies and flags them as direct or indirect.
// Note that it overwrites the existing package map.
func (a yarnAnalyzer) walkDependencies(parent *types.Package, pkgs map[string]types.Package, directDeps map[string]string,
	patterns map[string][]string, dev bool) error {

	// Identify direct dependencies
	seenIDs := set.New[string]()
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
				return xerrors.Errorf("unable to match version for %s", pkg.Name)
			} else if !match {
				continue
			}
		}

		// If the package is already marked as a production dependency, skip overwriting it.
		// Since the dev field is boolean, it cannot determine if the package is already processed,
		// so we need to check the relationship field.
		if pkg.Relationship == types.RelationshipUnknown || pkg.Dev {
			pkg.Dev = dev
		}

		// Mark as a direct dependency
		pkg.Indirect = false
		pkg.Relationship = types.RelationshipDirect

		pkgs[pkg.ID] = pkg
		seenIDs.Append(pkg.ID)

		// Add a direct dependency to the parent package
		parent.DependsOn = append(parent.DependsOn, pkg.ID)

		// Walk indirect dependencies
		a.walkIndirectDependencies(pkg, pkgs, seenIDs)
	}

	return nil
}

func (a yarnAnalyzer) walkIndirectDependencies(pkg types.Package, pkgs map[string]types.Package, seenIDs set.Set[string]) {
	for _, pkgID := range pkg.DependsOn {
		if seenIDs.Contains(pkgID) {
			continue // Skip if we've already seen this package
		}

		dep, ok := pkgs[pkgID]
		if !ok {
			continue
		}

		if dep.Relationship == types.RelationshipUnknown || dep.Dev {
			dep.Dev = pkg.Dev
		}
		dep.Indirect = true
		dep.Relationship = types.RelationshipIndirect
		pkgs[dep.ID] = dep

		seenIDs.Append(dep.ID)

		// Recursively walk dependencies
		a.walkIndirectDependencies(dep, pkgs, seenIDs)
	}
}

func (a yarnAnalyzer) traverseWorkspaces(fsys fs.FS, dir string, workspaces []string) ([]packagejson.Package, error) {
	var pkgs []packagejson.Package

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.NpmPkg
	}

	walkDirFunc := func(path string, _ fs.DirEntry, r io.Reader) error {
		pkg, err := a.packageJsonParser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", path, err)
		}
		pkg.Package.ID = cmp.Or(pkg.Package.ID, path) // In case the package.json doesn't have a name or version
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
		func(_ string, d fs.DirEntry, r io.Reader) error {
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
