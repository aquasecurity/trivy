package pip

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pip"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePip, newPipLibraryAnalyzer)
}

const version = 1

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
	var licenses = make(map[string][]string)

	if libDir, err := findLibDir(); err != nil || libDir == "" {
		a.logger.Warn("Unable to find python `lib` directory. License detection are skipped.", log.Err(err))
	} else {
		requiredMetadata := func(filePath string, _ fs.DirEntry) bool {
			return strings.HasSuffix(filepath.Dir(filePath), ".dist-info") && filepath.Base(filePath) == "METADATA"
		}

		// Detect licenses from python lib directory
		if err = fsutils.WalkDir(os.DirFS(libDir), ".", requiredMetadata, func(path string, d fs.DirEntry, r io.Reader) error {
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
			return nil, xerrors.Errorf("walk python lib dir error: %w", err)
		}
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

func findLibDir() (string, error) {
	// VIRTUAL_ENV
	if venv := os.Getenv("VIRTUAL_ENV"); venv != "" {
		libDir := filepath.Join(venv, "lib")
		if _, err := os.Stat(libDir); os.IsNotExist(err) {
			return "", xerrors.Errorf("Unable to detect `lib` dir for %q venv: %w", venv, err)
		}
		return libDir, nil
	}

	//find bins

	// default dir
	return "", nil
}

func packageID(name, ver string) string {
	return dependency.ID(types.Pip, name, ver)
}
