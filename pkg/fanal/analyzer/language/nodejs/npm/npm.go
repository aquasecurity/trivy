package npm

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/npm"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xpath "github.com/aquasecurity/trivy/pkg/x/path"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeNpmPkgLock, newNpmLibraryAnalyzer)
}

const (
	version = 1
)

type npmLibraryAnalyzer struct {
	logger        *log.Logger
	lockParser    language.Parser
	packageParser *packagejson.Parser
	licenseConfig types.LicenseScanConfig
}

var _ types.PackageManifestParser = (*npmLibraryAnalyzer)(nil)

func newNpmLibraryAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	analyzer := &npmLibraryAnalyzer{
		logger:        log.WithPrefix("npm"),
		lockParser:    npm.NewParser(),
		packageParser: packagejson.NewParser(),
	}

	if opt.LicenseScannerOption.Enabled && opt.LicenseScannerOption.Full {
		analyzer.licenseConfig = types.LicenseScanConfig{
			EnableDeepLicenseScan:     true,
			ClassifierConfidenceLevel: opt.LicenseScannerOption.ClassifierConfidenceLevel,
			LicenseTextCacheDir:       opt.LicenseScannerOption.LicenseTextCacheDir,
			LicenseScanWorkers:        opt.LicenseScannerOption.LicenseScanWorkers,
		}
		analyzer.logger.Debug("Deep license scanning enabled for Npm Library Analyzer")
	}

	return analyzer, nil
}

func (a npmLibraryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	// Parse package-lock.json
	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.NpmPkgLock
	}

	var apps []types.Application
	var looseLicenses []types.LicenseFile

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		// Find all licenses from package.json files under node_modules dirs
		// If deep license scanning is enabled, it also gets the concluded licenses.
		licensesMap, err := a.findLicenses(input.FS, filePath)
		if err != nil {
			a.logger.Error("Unable to collect licenses", log.Err(err))
			licensesMap = make(map[string][]types.License)
		}

		app, err := a.parseNpmPkgLock(input.FS, filePath)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Fill library licenses
		for i, lib := range app.Packages {
			if licenses, ok := licensesMap[lib.ID]; ok {
				for _, license := range licenses {
					// Declared license would be going to Licenses field as before
					// Concluded licenses would be going to ConcludedLicenses field
					if license.IsDeclared {
						app.Packages[i].Licenses = append(app.Packages[i].Licenses, license.Name)
					} else {
						app.Packages[i].ConcludedLicenses = append(app.Packages[i].ConcludedLicenses, license)
					}
				}
			}
		}

		// Fill loose licenses if any
		for _, license := range licensesMap[types.LOOSE_LICENSES] {
			looseLicense := types.LicenseFile{
				Type:     license.Type,
				FilePath: license.FilePath,
				Findings: license.Findings,
			}

			looseLicenses = append(looseLicenses, looseLicense)
		}

		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("package-lock.json/package.json walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
		Licenses:     looseLicenses,
	}, nil
}

func (a npmLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// Note: this is the main step where the file system is filtered and passed to above PostAnalyze API
	// Only files which pass this Required check would be added to the filtered file system
	if a.licenseConfig.EnableDeepLicenseScan {
		// TODO add some required checks to filter out files needed for deep license scanning

		// node_modules dir is scanned as part of findLicenses, so we skip it here
		// why only NpmPkgLock? this is the required file as part of PostAnalyze
		fileName := filepath.Base(filePath)
		if fileName == types.NpmPkgLock && xpath.Contains(filePath, "node_modules") {
			return false
		}

		return true
	}

	fileName := filepath.Base(filePath)
	// Don't save package-lock.json from the `node_modules` directory to avoid duplication and mistakes.
	if fileName == types.NpmPkgLock && !xpath.Contains(filePath, "node_modules") {
		return true
	}

	// Save package.json files only from the `node_modules` directory.
	// Required to search for licenses.
	if fileName == types.NpmPkg && xpath.Contains(filePath, "node_modules") {
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

func (a npmLibraryAnalyzer) parseNpmPkgLock(fsys fs.FS, filePath string) (*types.Application, error) {
	f, err := fsys.Open(filePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	file, ok := f.(xio.ReadSeekCloserAt)
	if !ok {
		return nil, xerrors.Errorf("type assertion error: %w", err)
	}

	// parse package-lock.json file
	return language.Parse(types.Npm, filePath, file, a.lockParser)
}

func (a npmLibraryAnalyzer) findLicenses(fsys fs.FS, lockPath string) (map[string][]types.License, error) {
	// If deep license scanning is enabled, we scan every file present in the repo and node_modules
	// and search for concluded licenses
	if a.licenseConfig.EnableDeepLicenseScan {
		return a.findConcludedLicenses(fsys, lockPath)
	}

	dir := path.Dir(lockPath)
	root := path.Join(dir, "node_modules")
	if _, err := fs.Stat(fsys, root); errors.Is(err, fs.ErrNotExist) {
		a.logger.Info(`To collect the license information of packages, "npm install" needs to be performed beforehand`,
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
	licenses := make(map[string][]types.License)
	err := fsutils.WalkDir(fsys, root, required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		pkg, err := a.packageParser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", filePath, err)
		}

		for _, license := range pkg.DeclaredLicenses() {
			licenses[pkg.PackageID()] = append(licenses[pkg.PackageID()], license)
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}
	return licenses, nil
}

func (a npmLibraryAnalyzer) findConcludedLicenses(fsys fs.FS, lockPath string) (map[string][]types.License, error) {
	dir := path.Dir(lockPath)
	dependencyRootPath := path.Join(dir, "node_modules")
	if _, err := fs.Stat(fsys, dependencyRootPath); errors.Is(err, fs.ErrNotExist) {
		a.logger.Info(`To collect the license information of packages, "npm install" needs to be performed beforehand`,
			log.String("dir", dependencyRootPath))
		return nil, nil
	}

	// Traverse node_modules dir and find licenses
	// Note that fs.FS is always slashed regardless of the platform,
	// and path.Join should be used rather than path.Join.

	walker, err := fsutils.NewRecursiveWalker(fsutils.RecursiveWalkerInput{
		Logger:                    a.logger,
		Parser:                    a,
		PackageManifestFile:       types.NpmPkg,
		PackageDependencyDir:      types.NpmDependencyDir,
		ClassifierConfidenceLevel: a.licenseConfig.ClassifierConfidenceLevel,
		LicenseTextCacheDir:       a.licenseConfig.LicenseTextCacheDir,
		ParallelWorkers:           a.licenseConfig.LicenseScanWorkers,
	})
	if err != nil {
		return nil, err
	}

	// Start the worker pool which sends data to license classifier
	walker.StartWorkerPool()

	// Process root path to find loose licenses
	if ret, err := walker.Walk(fsys, ".", ""); !ret || err != nil {
		a.logger.Error("Recursive walker has failed", log.String("dir", dir))
	}

	dirEntries, err := fs.ReadDir(fsys, dependencyRootPath)
	if err != nil {
		return nil, xerrors.Errorf("failed to read dir contents, err: %s", err.Error())
	}

	// Apply Recursive Walker on each dependency present in node_modules
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			dependencyPath := path.Join(dependencyRootPath, dirEntry.Name())

			if ret, err := walker.Walk(fsys, dependencyPath, ""); !ret || err != nil {
				a.logger.Error("Recursive walker has failed", log.String("dir", dependencyPath))
			}
		}
	}

	// exit the worker pool
	walker.StopWorkerPool()

	return walker.GetLicenses(), nil
}

// parses the package manifest file present at the given root path
func (a npmLibraryAnalyzer) ParseManifest(
	fsys fs.FS,
	path string,
) (types.PackageManifest, error) {
	fp, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	pkg, err := a.packageParser.Parse(fp)
	if err != nil {
		return pkg, xerrors.Errorf("err while parsing package manifest: %s", err.Error())
	}

	return pkg, nil
}
