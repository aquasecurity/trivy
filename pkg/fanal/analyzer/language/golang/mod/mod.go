package mod

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"go/build"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"unicode"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/mod"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/sum"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xpath "github.com/aquasecurity/trivy/pkg/x/path"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeGoMod, newGoModAnalyzer)
}

const version = 2

var (
	requiredFiles = []string{
		types.GoMod,
		types.GoSum,
	}
	licenseRegexp = regexp.MustCompile(`^(?i)((UN)?LICEN(S|C)E|COPYING|README|NOTICE).*$`)
)

type gomodAnalyzer struct {
	// root go.mod/go.sum
	modParser language.Parser
	sumParser language.Parser

	// go.mod/go.sum in dependencies
	leafModParser language.Parser

	licenseClassifierConfidenceLevel float64

	logger *log.Logger
}

func newGoModAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &gomodAnalyzer{
		modParser:                        mod.NewParser(true, opt.DetectionPriority == types.PriorityComprehensive), // Only the root module should replace
		sumParser:                        sum.NewParser(),
		leafModParser:                    mod.NewParser(false, false), // Don't detect stdlib for non-root go.mod files
		licenseClassifierConfidenceLevel: opt.LicenseScannerOption.ClassifierConfidenceLevel,
		logger:                           log.WithPrefix("golang"),
	}, nil
}

func (a *gomodAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.GoMod || input.FilePatterns.Match(path)
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, _ fs.DirEntry, _ io.Reader) error {
		// Parse go.mod
		gomod, err := parse(ctx, input.FS, path, a.modParser)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if gomod == nil {
			return nil
		}

		if lessThanGo117(gomod) {
			// e.g. /app/go.mod => /app/go.sum
			sumPath := filepath.Join(filepath.Dir(path), types.GoSum)
			gosum, err := parse(ctx, input.FS, sumPath, a.sumParser)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return xerrors.Errorf("parse error: %w", err)
			}
			mergeGoSum(gomod, gosum)
		}

		apps = append(apps, *gomod)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}

	if err = a.fillAdditionalData(ctx, input.FS, apps); err != nil {
		a.logger.Warn("Unable to collect additional info", log.Err(err))
	}

	// Add orphan indirect dependencies under the main module
	a.addOrphanIndirectDepsUnderRoot(apps)

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a *gomodAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)

	// Save required files (go.mod/go.sum)
	// Note: vendor directory doesn't contain these files, so we can skip checking for this.
	// See: https://github.com/aquasecurity/trivy/issues/8527#issuecomment-2777848027
	if slices.Contains(requiredFiles, fileName) {
		return true
	}

	// Save license files from vendor directory
	if licenseRegexp.MatchString(fileName) && xpath.Contains(filePath, "vendor") {
		return true
	}

	return false
}

func (a *gomodAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoMod
}

func (a *gomodAnalyzer) Version() int {
	return version
}

// fillAdditionalData collects licenses and dependency relationships, then update applications.
func (a *gomodAnalyzer) fillAdditionalData(ctx context.Context, fsys fs.FS, apps []types.Application) error {
	var modSearchDirs []searchDir

	// $GOPATH/pkg/mod
	if gopath, err := newGOPATH(); err != nil {
		a.logger.Debug("GOPATH not found. Run 'go mod download' or 'go mod tidy' for identifying dependency graph and licenses", log.Err(err))
	} else {
		modSearchDirs = append(modSearchDirs, gopath)
	}

	licenses := make(map[string][]string)
	for i, app := range apps {
		licenseSearchDirs := modSearchDirs

		// vendor directory next to go.mod
		if vendorDir, err := newVendorDir(fsys, app.FilePath); err == nil {
			licenseSearchDirs = append(licenseSearchDirs, vendorDir)
		}

		// Actually used dependencies
		usedPkgs := lo.SliceToMap(app.Packages, func(pkg types.Package) (string, types.Package) {
			return pkg.Name, pkg
		})

		// Check if either $GOPATH/pkg/mod or the vendor directory exists
		if len(licenseSearchDirs) == 0 {
			continue
		}

		for j, pkg := range app.Packages {
			// Collect licenses
			if licenseNames, err := findLicense(licenseSearchDirs, pkg, licenses, a.licenseClassifierConfidenceLevel); err != nil {
				return xerrors.Errorf("unable to collect license: %w", err)
			} else {
				// Fill licenses
				apps[i].Packages[j].Licenses = licenseNames
			}

			// Collect dependencies of the direct dependency from $GOPATH/pkg/mod because the vendor directory doesn't have go.mod files.
			dep, err := a.collectDeps(ctx, modSearchDirs, pkg)
			if err != nil {
				return xerrors.Errorf("dependency graph error: %w", err)
			} else if dep.ID == "" {
				// go.mod not found
				continue
			}
			// Filter out unused dependencies and convert module names to module IDs
			apps[i].Packages[j].DependsOn = lo.FilterMap(dep.DependsOn, func(modName string, _ int) (string, bool) {
				m, ok := usedPkgs[modName]
				if !ok {
					return "", false
				}
				return m.ID, true
			})
		}
	}
	return nil
}

func (a *gomodAnalyzer) collectDeps(ctx context.Context, searchDirs []searchDir, pkg types.Package) (types.Dependency, error) {
	for _, searchDir := range searchDirs {
		// e.g. $GOPATH/pkg/mod/github.com/aquasecurity/go-dep-parser@v0.1.0
		modDir, err := searchDir.Resolve(pkg)
		if err != nil {
			continue
		}

		dependsOn, err := a.resolveDeps(ctx, modDir)
		if errors.Is(err, fs.ErrNotExist) {
			a.logger.Debug("Unable to identify dependencies as it doesn't support Go modules",
				log.String("module", pkg.ID))
			return types.Dependency{}, nil
		} else if err != nil {
			return types.Dependency{}, xerrors.Errorf("resolve deps error: %w", err)
		}

		return types.Dependency{
			ID:        pkg.ID,
			DependsOn: dependsOn,
		}, nil
	}
	return types.Dependency{}, nil
}

// resolveDeps parses go.mod under $GOPATH/pkg/mod and returns the dependencies
func (a *gomodAnalyzer) resolveDeps(ctx context.Context, modDir fs.FS) ([]string, error) {
	// e.g. $GOPATH/pkg/mod/github.com/aquasecurity/go-dep-parser@v0.1.0/go.mod
	f, err := modDir.Open("go.mod")
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	file, ok := f.(xio.ReadSeekCloserAt)
	if !ok {
		return nil, xerrors.Errorf("type assertion error: %w", err)
	}

	// Parse go.mod under $GOPATH/pkg/mod
	pkgs, _, err := a.leafModParser.Parse(ctx, file)
	if err != nil {
		return nil, xerrors.Errorf("parse error: %w", err)
	}

	// Filter out indirect dependencies
	dependsOn := lo.FilterMap(pkgs, func(lib types.Package, _ int) (string, bool) {
		return lib.Name, lib.Relationship == types.RelationshipDirect
	})

	return dependsOn, nil

}

// addOrphanIndirectDepsUnderRoot handles indirect dependencies that have no identifiable parent packages in the dependency tree.
// This situation can occur when:
// - $GOPATH/pkg directory doesn't exist
// - Module cache is incomplete
// - etc.
//
// In such cases, indirect packages become "orphaned" - they exist in the dependency list
// but have no connection to the dependency tree. This function resolves this issue by:
// 1. Finding the root (main) module
// 2. Identifying all indirect dependencies that have no parent packages
// 3. Adding these orphaned indirect dependencies under the main module
//
// This ensures that all packages remain visible in the dependency tree, even when the complete
// dependency chain cannot be determined.
func (a *gomodAnalyzer) addOrphanIndirectDepsUnderRoot(apps []types.Application) {
	for _, app := range apps {
		// Find the main module
		_, rootIdx, found := lo.FindIndexOf(app.Packages, func(pkg types.Package) bool {
			return pkg.Relationship == types.RelationshipRoot
		})
		if !found {
			continue
		}

		// Collect all orphan indirect dependencies that are unable to identify parents
		parents := app.Packages.ParentDeps()
		orphanDeps := lo.FilterMap(app.Packages, func(pkg types.Package, _ int) (string, bool) {
			return pkg.ID, pkg.Relationship == types.RelationshipIndirect && len(parents[pkg.ID]) == 0
		})
		// Add orphan indirect dependencies under the main module
		app.Packages[rootIdx].DependsOn = append(app.Packages[rootIdx].DependsOn, orphanDeps...)
	}
}

func parse(ctx context.Context, fsys fs.FS, path string, parser language.Parser) (*types.Application, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	file, ok := f.(xio.ReadSeekCloserAt)
	if !ok {
		return nil, xerrors.Errorf("type assertion error: %w", err)
	}

	// Parse go.mod or go.sum
	return language.Parse(ctx, types.GoModule, path, file, parser)
}

func lessThanGo117(gomod *types.Application) bool {
	for _, lib := range gomod.Packages {
		// The indirect field is populated only in Go 1.17+
		if lib.Relationship == types.RelationshipIndirect {
			return false
		}
	}
	return true
}

func mergeGoSum(gomod, gosum *types.Application) {
	if gomod == nil || gosum == nil {
		return
	}
	uniq := make(map[string]types.Package)
	for _, lib := range gomod.Packages {
		// It will be used for merging go.sum.
		uniq[lib.Name] = lib
	}

	// For Go 1.16 or less, we need to merge go.sum into go.mod.
	for _, lib := range gosum.Packages {
		// Skip dependencies in go.mod so that go.mod should be preferred.
		if _, ok := uniq[lib.Name]; ok {
			continue
		}

		// This dependency doesn't exist in go.mod, so it must be an indirect dependency.
		lib.Indirect = true
		lib.Relationship = types.RelationshipIndirect
		uniq[lib.Name] = lib
	}

	gomod.Packages = lo.Values(uniq)
}

func findLicense(searchDirs []searchDir, pkg types.Package, licenses map[string][]string, classifierConfidenceLevel float64) ([]string, error) {
	if licenses[pkg.ID] != nil {
		return licenses[pkg.ID], nil
	}

	var license *types.LicenseFile
	for _, searchDir := range searchDirs {
		sub, err := searchDir.Resolve(pkg)
		if err != nil {
			continue
		}

		err = fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case !d.Type().IsRegular():
				return nil
			case !licenseRegexp.MatchString(filepath.Base(path)):
				return nil
			}

			// e.g. $GOPATH/pkg/mod/github.com/aquasecurity/go-dep-parser@v0.1.0/LICENSE
			f, err := sub.Open(path)
			if err != nil {
				return xerrors.Errorf("file (%s) open error: %w", path, err)
			}
			defer f.Close()

			if l, err := licensing.Classify(path, f, classifierConfidenceLevel); err != nil {
				return xerrors.Errorf("license classify error: %w", err)
			} else if l != nil && len(l.Findings) > 0 { // License found
				license = l
				return fs.SkipAll // Stop walking
			}
			return nil
		})

		switch {
		// The module path may not exist
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil && !errors.Is(err, io.EOF):
			return nil, xerrors.Errorf("unable to find a known open source license: %w", err)
		case license == nil || len(license.Findings) == 0:
			continue
		}

		// License found
		licenseNames := license.Findings.Names()
		licenses[pkg.ID] = licenseNames
		return licenseNames, nil
	}
	return nil, nil
}

// normalizeModName escapes upper characters
// e.g. 'github.com/BurntSushi/toml' => 'github.com/!burnt!sushi'
func normalizeModName(name string) string {
	var newName []rune
	for _, c := range name {
		if unicode.IsUpper(c) {
			// 'A' => '!a'
			newName = append(newName, '!', unicode.ToLower(c))
		} else {
			newName = append(newName, c)
		}
	}
	return string(newName)
}

type searchDir interface {
	Resolve(pkg types.Package) (fs.FS, error)
}

type gopathDir struct {
	root string
}

func newGOPATH() (searchDir, error) {
	gopath := cmp.Or(os.Getenv("GOPATH"), build.Default.GOPATH)

	// $GOPATH/pkg/mod
	modPath := filepath.Join(gopath, "pkg", "mod")
	if !fsutils.DirExists(modPath) {
		return nil, xerrors.Errorf("GOPATH not found: %s", modPath)
	}
	return &gopathDir{root: modPath}, nil
}

// Resolve resolves the module directory for a given package.
// It adds the version suffix to the module name and returns the directory as an fs.FS.
// e.g. $GOPATH/pkg/mod => $GOPATH/pkg/mod/github.com/aquasecurity/go-dep-parser@v1.0.0
func (d *gopathDir) Resolve(pkg types.Package) (fs.FS, error) {
	name := normalizeModName(pkg.Name)

	// Add version suffix for packages from $GOPATH
	// e.g. github.com/aquasecurity/go-dep-parser@v1.0.0
	modDirName := fmt.Sprintf("%s@%s", name, pkg.Version)

	// e.g. $GOPATH/pkg/mod/github.com/aquasecurity/go-dep-parser@v1.0.0
	modDir := filepath.Join(d.root, modDirName)
	return os.DirFS(modDir), nil
}

type vendorDir struct {
	root fs.FS
}

func newVendorDir(fsys fs.FS, modPath string) (vendorDir, error) {
	// vendor directory is in the same directory as go.mod
	vendor := filepath.Join(filepath.Dir(modPath), "vendor")
	sub, err := fs.Sub(fsys, vendor)
	if err != nil {
		return vendorDir{}, xerrors.Errorf("vendor directory not found: %w", err)
	}
	return vendorDir{root: sub}, nil
}

// Resolve resolves the module directory for a given package.
// It doesn't add the version suffix to the module name.
// e.g. vendor/ => vendor/github.com/aquasecurity/go-dep-parser
func (d vendorDir) Resolve(pkg types.Package) (fs.FS, error) {
	return fs.Sub(d.root, normalizeModName(pkg.Name))
}
