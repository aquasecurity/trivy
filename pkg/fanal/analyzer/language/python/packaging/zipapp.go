package packaging

import (
	"archive/zip"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	pythonpackaging "github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterAnalyzer(&zipAppAnalyzer{})
}

const (
	zipAppAnalyzerVersion = 1
	maxMetadataSize       = 10 << 20 // 10 MiB
)

type zipAppAnalyzer struct {
	logger                           *log.Logger
	licenseClassifierConfidenceLevel float64
}

func (a *zipAppAnalyzer) Init(opt analyzer.AnalyzerOptions) error {
	a.logger = log.WithPrefix("python")
	a.licenseClassifierConfidenceLevel = opt.LicenseScannerOption.ClassifierConfidenceLevel
	return nil
}

func (a *zipAppAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	if _, err := input.Content.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("file seek error: %w", err)
	}

	zr, err := zip.NewReader(input.Content, input.Info.Size())
	if err != nil {
		return nil, xerrors.Errorf("unable to open Python zipapp: %w", err)
	}

	var metadataFiles []*zip.File
	hasMain := false
	for _, f := range zr.File {
		if f.Name == "__main__.py" && !f.FileInfo().IsDir() {
			hasMain = true
		}
		if !f.FileInfo().IsDir() && isZipAppMetadata(f.Name) {
			metadataFiles = append(metadataFiles, f)
		}
	}
	if !hasMain {
		return nil, nil
	}

	var packages types.Packages
	for _, metadataFile := range metadataFiles {
		metadata, err := metadataFile.Open()
		if err != nil {
			return nil, xerrors.Errorf("unable to open Python package metadata %q: %w", metadataFile.Name, err)
		}

		rsa, err := xio.NewReadSeekerAt(xio.MaxBytesReader(metadata, maxMetadataSize))
		_ = metadata.Close()
		if err != nil {
			return nil, xerrors.Errorf("unable to read Python package metadata %q: %w", metadataFile.Name, err)
		}

		// metadataFile.Name is a validated relative path and is only used for reporting, not extraction.
		metadataPath := path.Join(input.FilePath, metadataFile.Name) // #nosec G305
		app, err := language.ParsePackage(ctx, types.PythonPkg, metadataPath, rsa,
			pythonpackaging.NewParser(), input.Options.FileChecksum)
		if err != nil {
			return nil, xerrors.Errorf("unable to parse Python package metadata %q: %w", metadataFile.Name, err)
		} else if app == nil {
			continue
		}

		opener := func(licensePath string) (io.ReadCloser, error) {
			name := path.Join(path.Dir(metadataFile.Name), licensePath)
			for _, f := range zr.File {
				if f.Name == name && !f.FileInfo().IsDir() {
					return f.Open()
				}
			}
			return nil, nil
		}
		if err = fillAdditionalData(opener, app, a.licenseClassifierConfidenceLevel); err != nil {
			a.logger.Warn("Unable to collect additional info", log.FilePath(metadataPath), log.Err(err))
		}

		packages = append(packages, app.Packages...)
	}
	if len(packages) == 0 {
		return nil, nil
	}

	return &analyzer.AnalysisResult{
		Applications: []types.Application{
			{
				Type:     types.PythonPkg,
				FilePath: input.FilePath,
				Packages: packages,
			},
		},
	}, nil
}

func isZipAppMetadata(filePath string) bool {
	if !fs.ValidPath(filePath) || strings.Contains(filePath, `\`) {
		return false
	}
	return strings.HasSuffix(filePath, ".dist-info/METADATA") || isEggFile(filePath)
}

func (a *zipAppAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	return strings.EqualFold(ext, ".pyz") || strings.EqualFold(ext, ".pyzw")
}

func (a *zipAppAnalyzer) Type() analyzer.Type {
	return analyzer.TypePythonPkgZipApp
}

func (a *zipAppAnalyzer) Version() int {
	return zipAppAnalyzerVersion
}
