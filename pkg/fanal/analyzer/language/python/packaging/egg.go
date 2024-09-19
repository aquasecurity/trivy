package packaging

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterAnalyzer(&eggAnalyzer{})
}

const (
	eggAnalyzerVersion = 1
	eggExt             = ".egg"
)

type eggAnalyzer struct {
	logger                           *log.Logger
	licenseClassifierConfidenceLevel float64
}

func (a *eggAnalyzer) Init(opt analyzer.AnalyzerOptions) error {
	a.logger = log.WithPrefix("python")
	a.licenseClassifierConfidenceLevel = opt.LicenseScannerOption.ClassifierConfidenceLevel
	return nil
}

// Analyze analyzes egg archive files
func (a *eggAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// .egg file is zip format and PKG-INFO needs to be extracted from the zip file.
	pkginfoInZip, err := findFileInZip(input.Content, input.Info.Size(), isEggFile)
	if err != nil {
		return nil, xerrors.Errorf("unable to open `.egg` archive: %w", err)
	}

	// Egg archive may not contain required files, then we will get nil. Skip this archives
	if pkginfoInZip == nil {
		return nil, nil
	}

	rsa, err := xio.NewReadSeekerAt(pkginfoInZip)
	if err != nil {
		return nil, xerrors.Errorf("unable to convert PKG-INFO reader: %w", err)
	}

	app, err := language.ParsePackage(types.PythonPkg, input.FilePath, rsa, packaging.NewParser(), input.Options.FileChecksum)
	if err != nil {
		return nil, xerrors.Errorf("parse error: %w", err)
	} else if app == nil {
		return nil, nil
	}

	opener := func(licPath string) (io.ReadCloser, error) {
		required := func(filePath string) bool {
			return path.Base(filePath) == licPath
		}

		f, err := findFileInZip(input.Content, input.Info.Size(), required)
		if err != nil {
			return nil, xerrors.Errorf("unable to find license file in `*.egg` file: %w", err)
		} else if f == nil { // zip doesn't contain license file
			return nil, nil
		}

		return f, nil
	}

	if err = fillAdditionalData(opener, app, a.licenseClassifierConfidenceLevel); err != nil {
		a.logger.Warn("Unable to collect additional info", log.Err(err))
	}

	return &analyzer.AnalysisResult{
		Applications: []types.Application{*app},
	}, nil
}

func findFileInZip(r xio.ReadSeekerAt, zipSize int64, required func(filePath string) bool) (io.ReadCloser, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("file seek error: %w", err)
	}

	zr, err := zip.NewReader(r, zipSize)
	if err != nil {
		return nil, xerrors.Errorf("zip reader error: %w", err)
	}

	found, ok := lo.Find(zr.File, func(f *zip.File) bool {
		return required(f.Name)
	})
	if !ok {
		return nil, nil
	}

	f, err := found.Open()
	if err != nil {
		return nil, xerrors.Errorf("unable to open file in zip: %w", err)
	}

	return f, nil
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
