package nuget

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nuget/config"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/nuget/lock"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeNuget, newNugetLibraryAnalyzer)
}

const (
	version    = 3
	lockFile   = types.NuGetPkgsLock
	configFile = types.NuGetPkgsConfig
)

var requiredFiles = []string{
	lockFile,
	configFile,
}

type nugetLibraryAnalyzer struct {
	lockParser    language.Parser
	configParser  language.Parser
	licenseParser nuspecParser
	logger        *log.Logger
}

func newNugetLibraryAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	logger := log.WithPrefix("nuget")
	analyzer := &nugetLibraryAnalyzer{
		lockParser:    lock.NewParser(),
		configParser:  config.NewParser(),
		licenseParser: newNuspecParser(logger),
		logger:        logger,
	}

	if opt.LicenseScannerOption.Enabled && opt.LicenseScannerOption.Full {
		analyzer.licenseParser.licenseConfig = types.LicenseScanConfig{
			EnableDeepLicenseScan:     true,
			ClassifierConfidenceLevel: opt.LicenseScannerOption.ClassifierConfidenceLevel,
			LicenseTextCacheDir:       opt.LicenseScannerOption.LicenseTextCacheDir,
			LicenseScanWorkers:        opt.LicenseScannerOption.LicenseScanWorkers,
		}
		analyzer.licenseParser.logger.Debug("Deep license scanning enabled for Nuget Library Analyzer")
	}

	return analyzer, nil
}

func (a *nugetLibraryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application
	foundLicenses := make(map[string][]types.License)

	var looseLicenses []types.LicenseFile

	// We save only config and lock files in the filtered FS,
	// so we need to parse all saved files
	// Note: If deep license scan is enabled, we'll save every file in the FS,
	// so explicit check is required here
	required := func(path string, d fs.DirEntry) bool {
		fileName := filepath.Base(path)
		return slices.Contains(requiredFiles, fileName)
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
		// Set the default parser
		parser := a.lockParser

		targetFile := filepath.Base(path)
		if targetFile == configFile {
			parser = a.configParser
		}

		app, err := language.Parse(types.NuGet, path, r, parser)
		if err != nil {
			return xerrors.Errorf("NuGet parse error: %w", err)
		}

		// nuget file doesn't contain dependencies
		if app == nil {
			return nil
		}

		var licenses []types.License
		var ok bool

		// Fill library licenses
		for i, lib := range app.Packages {
			licenses, ok = foundLicenses[lib.ID]
			if !ok {
				licenses, err = a.licenseParser.findLicense(lib.Name, lib.Version)
				if err != nil {
					return xerrors.Errorf("license find error: %w", err)
				}

				foundLicenses[lib.ID] = licenses
			}

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

		sort.Sort(app.Packages)
		apps = append(apps, *app)

		// Find loose licenses as well if deep license scanning is enabled
		if a.licenseParser.licenseConfig.EnableDeepLicenseScan {
			// Fill loose licenses found in the FS base path (i.e in "." dir of the FS)
			rootPathLicenses, err := a.licenseParser.findLicensesAtRootPath(input.FS)
			if err != nil {
				return xerrors.Errorf("license find error: %w", err)
			}

			for _, license := range rootPathLicenses {
				looseLicense := types.LicenseFile{
					Type:     license.Type,
					FilePath: license.FilePath,
					Findings: license.Findings,
				}

				looseLicenses = append(looseLicenses, looseLicense)
			}
		}

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("NuGet walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
		Licenses:     looseLicenses,
	}, nil
}

func (a *nugetLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// Note: this is the main step where the file system is filtered and passed to above PostAnalyze API
	// Only files which pass this Required check would be added to the filtered file system
	if a.licenseParser.licenseConfig.EnableDeepLicenseScan {
		return true
	}

	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a *nugetLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNuget
}

func (a *nugetLibraryAnalyzer) Version() int {
	return version
}
