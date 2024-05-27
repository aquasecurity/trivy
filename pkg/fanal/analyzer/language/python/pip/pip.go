package pip

import (
	"context"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
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

var pythonExecNames = []string{"python3", "python", "python2", "python.exe"}

type pipLibraryAnalyzer struct {
	logger         *log.Logger
	metadataParser packaging.Parser
}

func newPipLibraryAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return pipLibraryAnalyzer{
		logger:         log.WithPrefix("pip"),
		metadataParser: *packaging.NewParser(),
	}, nil
}

func (a pipLibraryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	licenses, err := a.licenseList()
	if err != nil {
		a.logger.Warn("Unable to find python `site-packages` directory. License detection is skipped.", log.Err(err))
	}

	// We only saved the `requirement.txt` files
	required := func(_ string, _ fs.DirEntry) bool {
		return true
	}

	if err := fsutils.WalkDir(input.FS, ".", required, func(pathPath string, d fs.DirEntry, r io.Reader) error {
		app, err := language.Parse(types.Pip, pathPath, r, pip.NewParser())
		if err != nil {
			return xerrors.Errorf("unable to parse requirements.txt: %w", err)
		}

		if app == nil {
			return nil
		}

		// Fill licenses
		for i, pkg := range app.Packages {
			pkgID := packageID(pkg.Name, pkg.Version)
			if lics, ok := licenses[pkgID]; ok {
				app.Packages[i].Licenses = lics
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

// licenseList returns list of licenses found in METADATA files in the `site-packages` directory.
func (a pipLibraryAnalyzer) licenseList() (map[string][]string, error) {
	var licenses = make(map[string][]string)

	spDir, err := pythonSitePackagesDir()
	if err != nil {
		return nil, xerrors.Errorf("Unable to find python `site-packages` directory: %w", err)
	}
	requiredMetadata := func(filePath string, _ fs.DirEntry) bool {
		return strings.HasSuffix(filepath.Dir(filePath), ".dist-info") && filepath.Base(filePath) == "METADATA"
	}

	// Detect licenses from `site-packages` directory
	if err = fsutils.WalkDir(os.DirFS(spDir), ".", requiredMetadata, func(path string, d fs.DirEntry, r io.Reader) error {
		rs, err := xio.NewReadSeekerAt(r)
		if err != nil {
			return xerrors.Errorf("Unable to convert reader: %w", err)
		}

		metadataPkg, _, err := a.metadataParser.Parse(rs)
		if err != nil {
			return xerrors.Errorf("metadata parse error: %w", err)
		}

		// METADATA file contains info about only 1 package
		licenses[packageID(metadataPkg[0].Name, metadataPkg[0].Version)] = metadataPkg[0].Licenses
		return nil
	}); err != nil {
		return nil, xerrors.Errorf("walk site-packages dir error: %w", err)
	}
	return licenses, nil
}

// pythonSitePackagesDir returns path to site-packages dir
func pythonSitePackagesDir() (string, error) {
	// check VIRTUAL_ENV first
	if venv := os.Getenv("VIRTUAL_ENV"); venv != "" {
		libDir := filepath.Join(venv, "lib")
		if _, err := os.Stat(libDir); os.IsNotExist(err) {
			return "", xerrors.Errorf("Unable to detect `lib` dir for %q venv: %w", venv, err)
		}

		spDir, err := findSitePackagesDir(libDir)
		if err != nil {
			return "", xerrors.Errorf("Unable to detect `site-packages` dir for %q venv: %w", spDir, err)
		}

		if spDir != "" {
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
	spDir, err := findSitePackagesDir(libDir)
	if err != nil {
		return "", xerrors.Errorf("Unable to detect `site-packages` dir for %q: %w", pythonExecPath, err)
	}
	if spDir != "" {
		return spDir, nil
	}

	// Try another common pattern if the Python library directory is not found
	spDir = filepath.Join(pythonExecDir, "..", "..", "lib", "site-packages")
	if _, err = os.Stat(spDir); os.IsNotExist(err) {
		return "", xerrors.Errorf("site-packages directory not found")
	}

	return spDir, nil
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
	return "", xerrors.Errorf("Unable to find path to Python executable")
}

// findSitePackagesDir finds `site-packages` dir in `lib` dir
func findSitePackagesDir(libDir string) (string, error) {
	entries, err := os.ReadDir(libDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", xerrors.Errorf("failed to read lib directory: %w", err)
		}
		return "", nil
	}

	// Use latest python dir
	var spDir string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "python") {
			// Found a directory starting with "python", assume it's the Python library directory
			dir := filepath.Join(libDir, entry.Name(), "site-packages")
			if _, err = os.Stat(dir); !os.IsNotExist(err) {
				spDir = filepath.Join(libDir, entry.Name(), "site-packages")
			}

		}
	}
	return spDir, nil
}

func packageID(name, ver string) string {
	return dependency.ID(types.Pip, name, ver)
}
