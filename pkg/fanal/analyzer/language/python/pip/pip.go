package pip

import (
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	goversion "github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pip"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePip, newPipLibraryAnalyzer)
}

const version = 1

var pythonExecNames = []string{
	"python3",
	"python",
	"python2",
	"python.exe",
}

type pipLibraryAnalyzer struct {
	logger            *log.Logger
	metadataParser    packaging.Parser
	detectionPriority types.DetectionPriority
}

func newPipLibraryAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return pipLibraryAnalyzer{
		logger:            log.WithPrefix("pip"),
		metadataParser:    *packaging.NewParser(),
		detectionPriority: opts.DetectionPriority,
	}, nil
}

func (a pipLibraryAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	sitePackagesDir, err := a.pythonSitePackagesDir()
	if err != nil {
		a.logger.Warn("Unable to find python `site-packages` directory. License detection is skipped.", log.Err(err))
	}

	required := func(_ string, _ fs.DirEntry) bool {
		// Parse all required files: `conan.lock` (from a.Required func) + input.FilePatterns.Match()
		return true
	}

	useMinVersion := a.detectionPriority == types.PriorityComprehensive

	if err = fsutils.WalkDir(input.FS, ".", required, func(pathPath string, _ fs.DirEntry, r io.Reader) error {
		app, err := language.Parse(ctx, types.Pip, pathPath, r, pip.NewParser(useMinVersion))
		if err != nil {
			return xerrors.Errorf("unable to parse requirements.txt: %w", err)
		}

		if app == nil {
			return nil
		}

		// Fill licenses
		if sitePackagesDir != "" {
			for i := range app.Packages {
				app.Packages[i].Licenses = a.pkgLicense(ctx, app.Packages[i].Name, app.Packages[i].Version, sitePackagesDir)
			}
		}

		apps = append(apps, *app)
		return nil
	}); err != nil {
		return nil, xerrors.Errorf("pip walt error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a pipLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return fileName == types.PipRequirements
}

func (a pipLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePip
}

func (a pipLibraryAnalyzer) Version() int {
	return version
}

// pkgLicense parses `METADATA` pkg file to look for licenses
func (a pipLibraryAnalyzer) pkgLicense(ctx context.Context, pkgName, pkgVer, spDir string) []string {
	metadataFile := a.metadataFile(pkgName, pkgVer, spDir)
	if metadataFile == nil {
		return nil
	}
	defer metadataFile.Close()

	metadataPkg, _, err := a.metadataParser.Parse(ctx, metadataFile)
	if err != nil {
		a.logger.Warn("Unable to parse METADATA file", log.FilePath(metadataFile.Name()), log.Err(err))
		return nil
	}

	// METADATA file contains info about only 1 package
	// cf. https://github.com/aquasecurity/trivy/blob/e66dbb935764908f0b2b9a55cbfe6c107f101a31/pkg/dependency/parser/python/packaging/parse.go#L86-L92
	return metadataPkg[0].Licenses
}

// pythonSitePackagesDir returns path to site-packages dir
func (a pipLibraryAnalyzer) pythonSitePackagesDir() (string, error) {
	// check VIRTUAL_ENV first
	if venv := os.Getenv("VIRTUAL_ENV"); venv != "" {
		libDir := filepath.Join(venv, "lib")
		if _, err := os.Stat(libDir); os.IsNotExist(err) {
			return "", xerrors.Errorf("unable to detect `lib` dir for %q venv: %w", venv, err)
		}

		spDir, err := a.findSitePackagesDir(libDir)
		if err != nil {
			return "", xerrors.Errorf("unable to detect `site-packages` dir for %q venv: %w", spDir, err)
		} else if spDir != "" {
			return spDir, nil
		}
	}

	// Find path to Python executable
	pythonExecPath, err := pythonExecutablePath()
	if err != nil {
		return "", err
	}
	pythonExecDir := filepath.Dir(pythonExecPath)

	// Search for a directory starting with "python" in the lib directory
	libDir := filepath.Join(pythonExecDir, "..", "lib")
	spDir, err := a.findSitePackagesDir(libDir)
	if err != nil {
		return "", xerrors.Errorf("unable to detect `site-packages` dir for %q: %w", pythonExecPath, err)
	} else if spDir != "" {
		return spDir, nil
	}

	// Try another common pattern if the Python library directory is not found
	spDir = filepath.Join(pythonExecDir, "..", "..", "lib", "site-packages")
	if fsutils.DirExists(spDir) {
		return spDir, nil
	}

	return "", xerrors.Errorf("site-packages directory not found")
}

// pythonExecutablePath returns path to Python executable
func pythonExecutablePath() (string, error) {
	for _, execName := range pythonExecNames {
		// Get the absolute path of the python command
		pythonPath, err := exec.LookPath(execName)
		if err != nil {
			continue
		}
		return pythonPath, nil
	}
	return "", xerrors.Errorf("unable to find path to Python executable")
}

// findSitePackagesDir finds `site-packages` dir in `lib` dir
func (a pipLibraryAnalyzer) findSitePackagesDir(libDir string) (string, error) {
	entries, err := os.ReadDir(libDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", xerrors.Errorf("failed to read lib directory: %w", err)
		}
		return "", nil
	}

	// Find python dir which contains `site-packages` dir
	// First check for newer versions
	pythonDirs := a.sortPythonDirs(entries)
	for i := len(pythonDirs) - 1; i >= 0; i-- {
		dir := filepath.Join(libDir, pythonDirs[i], "site-packages")
		if fsutils.DirExists(dir) {
			return dir, nil
		}
	}
	return "", nil
}

// sortPythonDirs finds dirs starting with `python` and sorts them
// e.g. python2.7 => python3.9 => python3.11
func (a pipLibraryAnalyzer) sortPythonDirs(entries []os.DirEntry) []string {
	var pythonVers []goversion.Version
	for _, entry := range entries {
		// Found a directory starting with "python", assume it's the Python library directory
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "python") {
			ver := strings.TrimPrefix(entry.Name(), "python")
			v, err := goversion.Parse(ver)
			if err != nil {
				a.logger.Debug("Unable to parse version from Python dir name", log.String("dir", entry.Name()), log.Err(err))
				continue
			}
			pythonVers = append(pythonVers, v)
		}
	}

	// Sort Python version
	sort.Sort(goversion.Collection(pythonVers))

	return lo.Map(pythonVers, func(v goversion.Version, _ int) string {
		return "python" + v.String()
	})
}

// metadataFile returns METADATA file for package (if exists)
func (a pipLibraryAnalyzer) metadataFile(pkgName, pkgVer, spDir string) *os.File {
	pkgDirs := distInfoDirs(pkgName, pkgVer)
	for _, pkgDir := range distInfoDirs(pkgName, pkgVer) {
		metadataPath := filepath.Join(spDir, pkgDir, "METADATA")
		metadataFile, err := os.Open(metadataPath)
		if err == nil {
			return metadataFile
		}
	}

	a.logger.Debug("No package metadata found", log.String("site-packages", spDir),
		log.String("dist-info", strings.Join(pkgDirs, ", ")), log.String("name", pkgName), log.String("version", pkgVer))
	return nil
}

// distInfoDir returns normalized dist-info dir name for package
// cf. https://packaging.python.org/en/latest/specifications/recording-installed-packages/#the-dist-info-directory
// e.g. `foo-1.0.dist-info` or `foo_bar-1.0.dist-info`
func distInfoDirs(name, version string) []string {
	dirs := []string{
		// Any packages don't use lower case.
		// e.g. Flask uses `Flask-2.0.1.dist-info`
		python.NormalizePkgName(name, false),
		python.NormalizePkgName(name, true),
	}

	for i := range dirs {
		dirs[i] = strings.ReplaceAll(dirs[i], "-", "_")
		dirs[i] = dirs[i] + "-" + version + ".dist-info"
	}

	return dirs
}
