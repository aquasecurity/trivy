package conan

import (
	"bufio"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/c/conan"
	godeptypes "github.com/aquasecurity/trivy/pkg/dependency/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeConanLock, newConanLockAnalyzer)
}

const (
	version = 2
)

// conanLockAnalyzer analyzes conan.lock
type conanLockAnalyzer struct {
	parser godeptypes.Parser
}

func newConanLockAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return conanLockAnalyzer{
		parser: conan.NewParser(),
	}, nil
}

func (a conanLockAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	required := func(filePath string, d fs.DirEntry) bool {
		return a.Required(filePath, nil)
	}

	licenses, err := licensesFromCache()
	if err != nil {
		log.Logger.Debugf("Unable to parse cache directory to obtain licenses: %s", err)
	}

	var apps []types.Application
	if err = fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		app, err := language.Parse(types.Conan, filePath, r, a.parser)
		if err != nil {
			return xerrors.Errorf("%s parse error: %w", filePath, err)
		}

		// Fill licenses
		for i, lib := range app.Libraries {
			if license, ok := licenses[lib.Name]; ok {
				app.Libraries[i].Licenses = []string{
					license,
				}
			}
		}

		apps = append(apps, *app)
		return nil
	}); err != nil {
		return nil, xerrors.Errorf("unable to parse conan lock file: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func licensesFromCache() (map[string]string, error) {
	required := func(filePath string, d fs.DirEntry) bool {
		return filepath.Base(filePath) == "conanfile.py"
	}

	// cf. https://docs.conan.io/1/mastering/custom_cache.html
	cacheDir := os.Getenv("CONAN_USER_HOME")
	if cacheDir == "" {
		cacheDir, _ = os.UserHomeDir()
	}
	cacheDir = path.Join(cacheDir, ".conan", "data")

	if !fsutils.DirExists(cacheDir) {
		log.Logger.Debugf("The Conan cache directory (%s) was not found. Package licenses will be skipped", cacheDir)
		return nil, nil
	}

	licenses := make(map[string]string)
	if err := fsutils.WalkDir(os.DirFS(cacheDir), ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		scanner := bufio.NewScanner(r)
		var name, license string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if strings.HasPrefix(line, "name") { // cf. https://docs.conan.io/1/reference/conanfile/attributes.html#name
				// trim extra characters - e.g. `name = "openssl"` -> `openssl`
				name = strings.TrimSuffix(strings.TrimPrefix(line, `name = "`), `"`)
				// Check that the license is already found
				if license != "" {
					break
				}
			} else if strings.HasPrefix(line, "license") { // cf. https://docs.conan.io/1/reference/conanfile/attributes.html#license
				// trim extra characters - e.g. `license = "Apache-2.0"` -> `Apache-2.0`
				license = strings.TrimSuffix(strings.TrimPrefix(line, `license = "`), `"`)
				// Check that the name is already found
				if name != "" {
					break
				}
			}
		}

		// Skip files without name/license
		if name == "" || license == "" {
			return nil
		}

		licenses[name] = license
		return nil
	}); err != nil {
		return nil, xerrors.Errorf("conan cache dir (%s) walk error: %w", cacheDir, err)
	}
	return licenses, nil
}

func (a conanLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// Lock file name can be anything
	// cf. https://docs.conan.io/1/versioning/lockfiles/introduction.html#locking-dependencies
	// By default, we only check the default filename - `conan.lock`.
	return filepath.Base(filePath) == types.ConanLock
}

func (a conanLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypeConanLock
}

func (a conanLockAnalyzer) Version() int {
	return version
}
