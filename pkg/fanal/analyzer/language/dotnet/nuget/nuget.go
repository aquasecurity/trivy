package nuget

import (
	"context"
	"errors"
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

func newNugetLibraryAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &nugetLibraryAnalyzer{
		lockParser:    lock.NewParser(),
		configParser:  config.NewParser(),
		licenseParser: newNuspecParser(),
		logger:        log.WithPrefix("nuget"),
	}, nil
}

func (a *nugetLibraryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application
	foundLicenses := make(map[string][]string)
	if a.licenseParser.packagesDir == "" {
		a.logger.Debug("The nuget packages directory couldn't be found. License search disabled")
	}

	// We saved only config and lock files in the FS,
	// so we need to parse all saved files
	required := func(path string, d fs.DirEntry) bool {
		return true
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

		for i, lib := range app.Packages {
			license, ok := foundLicenses[lib.ID]
			if !ok {
				license, err = a.licenseParser.findLicense(lib.Name, lib.Version)
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return xerrors.Errorf("license find error: %w", err)
				}
				foundLicenses[lib.ID] = license
			}

			app.Packages[i].Licenses = license
		}

		sort.Sort(app.Packages)
		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("NuGet walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a *nugetLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a *nugetLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNuget
}

func (a *nugetLibraryAnalyzer) Version() int {
	return version
}
