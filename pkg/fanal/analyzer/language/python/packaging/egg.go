package packaging

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePythonPkgEgg, newEggAnalyzer)
}

const (
	eggAnalyzerVersion = 1
	eggExt             = ".egg"
)

func newEggAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &eggAnalyzer{
		logger:                           log.WithPrefix("python"),
		pkgParser:                        packaging.NewParser(),
		licenseClassifierConfidenceLevel: opts.LicenseScannerOption.ClassifierConfidenceLevel,
	}, nil
}

type eggAnalyzer struct {
	logger                           *log.Logger
	pkgParser                        language.Parser
	licenseClassifierConfidenceLevel float64
}

// PostAnalyze analyzes egg archive files
func (a eggAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return a.Required(path, nil) || slices.Contains(input.FilePathsMatchedFromPatterns, path)
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
		rsa, ok := r.(xio.ReadSeekerAt)
		if !ok {
			return xerrors.New("invalid reader")
		}

		// .egg file is zip format and PKG-INFO needs to be extracted from the zip file.
		info, err := d.Info()
		if err != nil {
			return xerrors.Errorf("egg file error: %w", err)
		}
		pkginfoInZip, err := a.findFileInZip(rsa, info.Size(), isEggFile)
		if err != nil {
			return xerrors.Errorf("egg analysis error: %w", err)
		}

		// Egg archive may not contain required files, then we will get nil. Skip this archives
		if pkginfoInZip == nil {
			return nil
		}

		app, err := language.ParsePackage(types.PythonPkg, path, pkginfoInZip, a.pkgParser, input.Options.FileChecksum)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		if err = a.fillLicensesFromFile(rsa, info.Size(), app); err != nil {
			a.logger.Warn("Unable to fill licenses", log.FilePath(path), log.Err(err))
		}

		apps = append(apps, *app)
		return nil
	})

	if err != nil {
		return nil, xerrors.Errorf("python package walk error: %w", err)
	}
	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a eggAnalyzer) findFileInZip(r xio.ReadSeekerAt, size int64, required func(filePath string) bool) (xio.ReadSeekerAt, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("file seek error: %w", err)
	}

	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, xerrors.Errorf("zip reader error: %w", err)
	}

	found, ok := lo.Find(zr.File, func(f *zip.File) bool {
		return required(f.Name)
	})
	if !ok {
		return nil, nil
	}
	return a.open(found)
}

// open reads the file content in the zip archive to make it seekable.
func (a eggAnalyzer) open(file *zip.File) (xio.ReadSeekerAt, error) {
	f, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, xerrors.Errorf("file %s open error: %w", file.Name, err)
	}

	return bytes.NewReader(b), nil
}

func (a eggAnalyzer) fillLicensesFromFile(r xio.ReadSeekerAt, size int64, app *types.Application) error {
	for i, pkg := range app.Packages {
		var licenses []string
		for _, license := range pkg.Licenses {
			if !strings.HasPrefix(license, "file://") {
				licenses = append(licenses, license)
				continue
			}

			required := func(filePath string) bool {
				return path.Base(filePath) == path.Base(strings.TrimPrefix(license, "file://"))
			}
			lr, err := a.findFileInZip(r, size, required)
			if err != nil {
				a.logger.Debug("unable to find license file in `*.egg` file", log.Err(err))
				continue
			} else if lr == nil { // zip doesn't contain license file
				continue
			}

			l, err := licensing.Classify("", lr, a.licenseClassifierConfidenceLevel)
			if err != nil {
				return xerrors.Errorf("license classify error: %w", err)
			} else if l == nil {
				continue
			}

			// License found
			foundLicenses := lo.Map(l.Findings, func(finding types.LicenseFinding, _ int) string {
				return finding.Name
			})
			licenses = append(licenses, foundLicenses...)
		}
		app.Packages[i].Licenses = licenses
	}
	return nil
}

func (a eggAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Ext(filePath) == eggExt
}

func (a eggAnalyzer) Type() analyzer.Type {
	return analyzer.TypePythonPkgEgg
}

func (a eggAnalyzer) Version() int {
	return eggAnalyzerVersion
}
