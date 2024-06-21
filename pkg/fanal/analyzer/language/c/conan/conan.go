package conan

import (
	"bufio"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/c/conan"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
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
	logger *log.Logger
	parser language.Parser
}

func newConanLockAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return conanLockAnalyzer{
		logger: log.WithPrefix("conan"),
		parser: conan.NewParser(),
	}, nil
}

func (a conanLockAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	required := func(filePath string, d fs.DirEntry) bool {
		// we need all file got from `a.Required` function (conan.lock files) and from file-patterns.
		return true
	}

	licenses, err := licensesFromCache()
	if err != nil {
		a.logger.Debug("Unable to parse cache directory to obtain licenses", log.Err(err))
	}

	var apps []types.Application
	if err = fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		app, err := language.Parse(types.Conan, filePath, r, a.parser)
		if err != nil {
			return xerrors.Errorf("%s parse error: %w", filePath, err)
		}

		if app == nil {
			return nil
		}

		// Fill licenses
		for i, lib := range app.Packages {
			if license, ok := licenses[lib.Name]; ok {
				app.Packages[i].Licenses = []string{
					license,
				}
			}
		}

		sort.Sort(app.Packages)
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
	cacheDir, err := detectCacheDir()
	if err != nil {
		return nil, err
	}

	required := func(filePath string, d fs.DirEntry) bool {
		return filepath.Base(filePath) == "conanfile.py"
	}

	licenses := make(map[string]string)
	if err := fsutils.WalkDir(os.DirFS(cacheDir), ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		scanner := bufio.NewScanner(r)
		var name, license string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			// cf. https://docs.conan.io/1/reference/conanfile/attributes.html#name
			if n := detectAttribute("name", line); n != "" {
				name = n
				// Check that the license is already found
				if license != "" {
					break
				}
			}
			// cf. https://docs.conan.io/1/reference/conanfile/attributes.html#license
			if l := detectAttribute("license", line); l != "" {
				license = l
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
		return nil, xerrors.Errorf("the Conan cache dir (%s) walk error: %w", cacheDir, err)
	}
	return licenses, nil
}

// detectAttribute detects conan attribute (name, license, etc.) from line
// cf. https://docs.conan.io/1/reference/conanfile/attributes.html
func detectAttribute(attributeName, line string) string {
	if !strings.HasPrefix(line, attributeName) {
		return ""
	}

	// e.g. `license = "Apache or MIT"` -> ` "Apache or MIT"` -> `"Apache or MIT"` -> `Apache or MIT`
	if name, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(name) == attributeName {
		attr := strings.TrimSpace(v)
		return strings.Trim(attr, `"`)
	}

	return ""
}

func detectCacheDir() (string, error) {
	home, _ := os.UserHomeDir()
	dirs := []string{
		// conan v2 uses `CONAN_HOME` env
		// cf. https://docs.conan.io/2/reference/environment.html#conan-home
		// `.conan2` dir is omitted for this env
		lo.Ternary(os.Getenv("CONAN_HOME") != "", path.Join(os.Getenv("CONAN_HOME"), "p"), ""),
		// conan v1 uses `CONAN_USER_HOME` env
		// cf. https://docs.conan.io/en/1.64/reference/env_vars.html#conan-user-home
		// `.conan` dir is used for this env
		lo.Ternary(os.Getenv("CONAN_USER_HOME") != "", path.Join(os.Getenv("CONAN_USER_HOME"), ".conan", "data"), ""),
		// `<username>/.conan2` is default directory for conan v2
		// cf. https://docs.conan.io/2/reference/environment.html#conan-home
		path.Join(home, ".conan2", "p"),
		// `<username>/.conan` is default directory for conan v1
		// cf. https://docs.conan.io/1/mastering/custom_cache.html
		path.Join(home, ".conan", "data"),
	}

	for _, dir := range dirs {
		if dir != "" {
			if fsutils.DirExists(dir) {
				return dir, nil
			}
		}
	}

	return "", xerrors.Errorf("the Conan cache directory was not found.")
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
