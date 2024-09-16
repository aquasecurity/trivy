package packaging

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterAnalyzer(&eggAnalyzer{})
}

func (a *eggAnalyzer) Init(opt analyzer.AnalyzerOptions) error {
	a.logger = log.WithPrefix("python")
	a.licenseClassifierConfidenceLevel = opt.LicenseScannerOption.ClassifierConfidenceLevel
	return nil
}

const (
	eggAnalyzerVersion = 1
	eggExt             = ".egg"
)

type eggAnalyzer struct {
	logger                           *log.Logger
	licenseClassifierConfidenceLevel float64
}

// Analyze analyzes egg archive files
func (a *eggAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// .egg file is zip format and PKG-INFO needs to be extracted from the zip file.
	pkginfoInZip, err := findFileInZip(input.Content, input.Info.Size(), isEggFile)
	if err != nil {
		return nil, xerrors.Errorf("egg analysis error: %w", err)
	}

	// Egg archive may not contain required files, then we will get nil. Skip this archives
	if pkginfoInZip == nil {
		return nil, nil
	}

	app, err := language.ParsePackage(types.PythonPkg, input.FilePath, pkginfoInZip, packaging.NewParser(), input.Options.FileChecksum)
	if err != nil {
		return nil, xerrors.Errorf("parse error: %w", err)
	} else if app == nil {
		return nil, nil
	}

	if err = a.fillLicensesFromFile(input.Content, input.Info.Size(), app); err != nil {
		a.logger.Warn("Unable to fill licenses", log.FilePath(input.FilePath), log.Err(err))
	}

	return &analyzer.AnalysisResult{
		Applications: []types.Application{*app},
	}, nil
}

func findFileInZip(r xio.ReadSeekerAt, size int64, required func(filePath string) bool) (xio.ReadSeekerAt, error) {
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
	return openFile(found)
}

// openFile reads the file content in the zip archive to make it seekable.
func openFile(file *zip.File) (xio.ReadSeekerAt, error) {
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

func (a *eggAnalyzer) fillLicensesFromFile(r xio.ReadSeekerAt, size int64, app *types.Application) error {
	for i, pkg := range app.Packages {
		var licenses []string
		for _, license := range pkg.Licenses {
			if !strings.HasPrefix(license, licensing.LicenseFilePrefix) {
				licenses = append(licenses, license)
				continue
			}

			required := func(filePath string) bool {
				return path.Base(filePath) == path.Base(strings.TrimPrefix(license, licensing.LicenseFilePrefix))
			}
			f, err := findFileInZip(r, size, required)
			if err != nil {
				a.logger.Debug("unable to find license file in `*.egg` file", log.Err(err))
				continue
			} else if f == nil { // zip doesn't contain license file
				continue
			}

			l, err := licensing.Classify("", f, a.licenseClassifierConfidenceLevel)
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

func (a *eggAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Ext(filePath) == eggExt
}

func (a *eggAnalyzer) Type() analyzer.Type {
	return analyzer.TypePythonPkgEgg
}

func (a *eggAnalyzer) Version() int {
	return eggAnalyzerVersion
}
